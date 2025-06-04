from fastapi import FastAPI, Request, Response, Query
from fastapi.responses import JSONResponse
import aiohttp
import logging
import json
import re
import os
import httpx
import asyncio
import ssl
import uvicorn
import os
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

app = FastAPI()

PORT = 3000

TOKEN = "TERAXBOTZ"

COOKIE = "browserid=cLNycJqGL6eOGpkhz9CtW3sG7CS89UeNe0Ycq2Ainq-UD9VlRDZiyB8tBaI=; lang=en; TSID=7neW7n6LXenkJEV0l9xwoXc87YgeObNR; __bid_n=1971ea13b40eefcf4f4207; _ga=GA1.1.113339747.1748565576; ndus=YvZErXkpeHui6z7tOvOuDPvaDsYiQOZosuA0eNJq; csrfToken=7rbF54M2IP5Hy8dh_ZCHGIFY"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "application/json",
    "Accept-Language": "en-US,en;q=0.9",
    "Cookie": COOKIE,
    "Referer": "https://www.terabox.com/"
}

@app.get("/")
async def handler(request: Request, url: str = Query(None), token: str = Query(None)):
    print('[MAIN] Starting request processing', { "method": request.method, "query": {"url": url, "token": token} })

    if request.method == "OPTIONS":
        print('[MAIN] Handling CORS preflight request')
        response = Response(status_code=200)
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Methods"] = "GET, OPTIONS"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type"
        print('[MAIN] CORS response sent', { "status": 200 })
        return response

    if request.method != "GET":
        print('[MAIN] Invalid method received', { "method": request.method })
        return JSONResponse(status_code=405, content={"success": False, "error": "Method not allowed"})

    print('[MAIN] Parsed query parameters', { "teraboxUrl": url, "token": token })

    if not url or not token:
        print('[MAIN] Missing parameters', { "urlExists": bool(url), "tokenExists": bool(token) })
        return JSONResponse(status_code=400, content={"success": False, "error": "Missing url or token"})

    if token != TOKEN:
        print('[MAIN] Invalid token provided', { "received": token, "expected": TOKEN })
        return JSONResponse(status_code=401, content={"success": False, "error": "Invalid Token"})

    try:
        # `process_terabox_share` will be provided by you
        result = await processTeraboxShare(url)
        print('[MAIN] Processing completed', { "result": { "success": result["success"], "isFolder": result["isFolder"], "dataLength": len(result["data"]) } })
        return JSONResponse(status_code=200, content={"success": True, **result})
    except Exception as error:
        print('[MAIN] Unhandled error', { "message": str(error) })
        return JSONResponse(status_code=500, content={"success": False, "error": str(error)})

async def processTeraboxShare(share_url):
    logging.info("[PROCESS_TERABOX_SHARE] Starting", {'shareUrl': share_url})
    try:
        surl = getSurl(share_url)
        logging.info("[PROCESS_TERABOX_SHARE] Extracted surl", {'surl': surl})
        if not surl:
            raise Exception("Invalid Terabox URL")

        html, final_url = await fetchPage(share_url)
        logging.info("[PROCESS_TERABOX_SHARE] Page fetched", {'finalUrl': final_url, 'htmlLength': len(html)})

        listsurl = getSurl(final_url)
        logging.info("[PROCESS_TERABOX_SHARE] Extracted listsurl", {'listsurl': listsurl})
        if not listsurl:
            raise Exception("Failed to extract listsurl")

        jsToken, bdstoken = extractTokens(html)
        logging.info("[PROCESS_TERABOX_SHARE] Extracted tokens", {'jsToken': bool(jsToken), 'bdstoken': bool(bdstoken)})
        if not jsToken or not bdstoken:
            raise Exception("Token extraction failed")

        metadata = await getFileMetadata(surl)
        logging.info("[PROCESS_TERABOX_SHARE] Metadata fetched", {
            'listLength': len(metadata['list']) if metadata.get('list') else 0,
            'shareid': metadata.get('shareid'),
            'uk': metadata.get('uk')
        })

        if not metadata.get('list'):
            raise Exception("No files found in metadata")

        logid = await extractLogid(html, listsurl, jsToken, metadata)
        logging.info("[PROCESS_TERABOX_SHARE] Extracted logid", {'logid': logid})
        if not logid:
            raise Exception("Failed to extract DP log ID")

        is_folder = metadata['list'][0]['isdir'] == 1
        logging.info("[PROCESS_TERABOX_SHARE] Resource type", {'isFolder': is_folder})

        list_data = await fetchFileList({
            'metadata': metadata,
            'surl': surl,
            'tokens': {
                'jsToken': jsToken,
                'logid': logid,
                'bdstoken': bdstoken,
                'listsurl': listsurl
            }
        })
        logging.info("[PROCESS_TERABOX_SHARE] File list fetched", {'itemCount': len(list_data)})

        files = await processListData(list_data, metadata, {
            'jsToken': jsToken,
            'logid': logid,
            'bdstoken': bdstoken
        })
        filtered_files = list(filter(None, files))
        logging.info("[PROCESS_TERABOX_SHARE] Files processed", {'fileCount': len(filtered_files)})

        result = {
            'success': True,
            'isFolder': is_folder,
            'data': filtered_files
        }
        logging.info("[PROCESS_TERABOX_SHARE] Returning result", {
            'success': result['success'],
            'isFolder': is_folder,
            'dataLength': len(result['data'])
        })
        return result

    except Exception as e:
        logging.error("[PROCESS_TERABOX_SHARE] Failed", {'message': str(e)})
        raise

async def fetchFileList(context):
    metadata = context['metadata']
    surl = context['surl']
    tokens = context['tokens']

    logging.info("[FETCH_FILE_LIST] Starting", {
        'surl': surl,
        'tokens': {k: bool(v) for k, v in tokens.items()},
        'metadata': {'shareid': metadata['shareid'], 'uk': metadata['uk']}
    })

    try:
        is_folder = metadata['list'][0]['isdir'] == 1
        logging.info("[FETCH_FILE_LIST] Resource is folder", {'isFolder': is_folder})

        list_url = "https://www.1024tera.com/share/list"
        params = {
            'app_id': '250528',
            'web': '1',
            'jsToken': tokens['jsToken'],
            'shorturl': tokens['listsurl'],
            'shareid': metadata['shareid'],
            'uk': metadata['uk'],
            'dp-logid': tokens['logid'],
            'sign': metadata['sign'],
            'timestamp': metadata['timestamp'],
            'root': 0 if is_folder else 1,
            'page': '1',
            'num': '1000',
            'dir': metadata['list'][0]['path'] if is_folder else '/'
        }

        parsed_host = urlparse(list_url).hostname
        dynamic_headers = {
            **headers,
            "Host": parsed_host,
            "Referer": f"https://{parsed_host}/",
            "Origin": f"https://{parsed_host}"
        }
        logging.info("[FETCH_FILE_LIST] Request headers", {
            'Host': dynamic_headers['Host'],
            'Referer': dynamic_headers['Referer'],
            'Cookie': 'exists' if 'Cookie' in dynamic_headers else 'missing'
        })

        async with aiohttp.ClientSession() as session:
            async with session.get(list_url, headers=dynamic_headers, params=params) as response:
                logging.info("[FETCH_FILE_LIST] Response received", {'status': response.status, 'url': str(response.url)})
                data = await response.json()
                logging.info("[FETCH_FILE_LIST] Response data", {
                    'keys': list(data.keys()),
                    'listLength': len(data.get('list', []))
                })

                if not data.get('list'):
                    logging.error("[FETCH_FILE_LIST] Empty response from API", {'data': data})
                    raise Exception("Empty response from list API")

                logging.info("[FETCH_FILE_LIST] Returning list", {'itemCount': len(data['list'])})
                return data['list']

    except Exception as e:
        logging.error("[FETCH_FILE_LIST] Failed", {'message': str(e)})
        raise

async def processListData(file_list, metadata, tokens):
    print('[PROCESS_LIST_DATA] Starting', {
        'listLength': len(file_list),
        'metadata': {'shareid': metadata['shareid']},
        'tokens': {k: bool(tokens.get(k)) for k in ['jsToken', 'logid', 'bdstoken']}
    })
    try:
        batches = [file_list[i:i + 50] for i in range(0, len(file_list), 50)]
        print('[PROCESS_LIST_DATA] Created batches', {'batchCount': len(batches)})

        results = []
        for index, batch in enumerate(batches):
            print('[PROCESS_LIST_DATA] Processing batch', {'batchIndex': index + 1, 'batchSize': len(batch)})
            batch_results = await asyncio.gather(*(process_list_item(item, metadata, tokens) for item in batch))
            print('[PROCESS_LIST_DATA] Batch results', {'batchIndex': index + 1, 'resultCount': len(batch_results)})
            results.extend(batch_results)

        print('[PROCESS_LIST_DATA] Returning results', {'totalResults': len(results)})
        return results
    except Exception as e:
        print('[PROCESS_LIST_DATA] Failed', {'message': str(e)})
        raise


async def process_list_item(item, metadata, tokens):
    print('[PROCESS_LIST_ITEM] Starting', {
        'filename': item['server_filename'],
        'isdir': item['isdir'],
        'metadata': {'shareid': metadata['shareid']},
        'tokens': {k: bool(tokens.get(k)) for k in ['jsToken', 'logid', 'bdstoken']}
    })
    try:
        if item['isdir'] == 1:
            print('[PROCESS_LIST_ITEM] Handling folder', {'filename': item['server_filename']})
            result = {
                'filename': item['server_filename'],
                'path': item['path'],
                'is_folder': True
            }
            print('[PROCESS_LIST_ITEM] Folder result', result)
            return result

        file_dlink = await get_file_dlink(item, metadata, tokens)
        print('[PROCESS_LIST_ITEM] Download link fetched', {'dllink': file_dlink['dllink']})

        result = {
            'filename': item['server_filename'],
            'path': item['path'],
            'size': format_size(item['size']),
            'sizebytes': int(item.get('size', 0)),
            'dlink': file_dlink['dllink'],
            'thumb': item.get('thumbs', {}).get('url3', None),
            'is_folder': False
        }
        print('[PROCESS_LIST_ITEM] File result', result)
        return result
    except Exception as e:
        print('[PROCESS_LIST_ITEM] Failed', {
            'filename': item['server_filename'],
            'message': str(e)
        })
        error_result = {
            'filename': item['server_filename'],
            'path': item['path'],
            'size': format_size(item.get('size', 0)),
            'sizebytes': int(item.get('size', 0)),
            'error': str(e),
            'is_folder': item['isdir'] == 1
        }
        print('[PROCESS_LIST_ITEM] Error result', error_result)
        return error_result


async def get_file_dlink(file, metadata, tokens):
    print('[GET_FILE_DLINK] Starting', {
        'filename': file['server_filename'],
        'fs_id': file['fs_id'],
        'metadata': {
            'shareid': metadata['shareid'],
            'sign': metadata['sign'],
            'timestamp': metadata['timestamp']
        },
        'tokens': {
            'jsToken': bool(tokens.get('jsToken')),
            'bdstoken': bool(tokens.get('bdstoken')),
            'logid': tokens.get('logid')
        }
    })
    try:
        query_params = {
            'app_id': '250528',
            'web': '1',
            'channel': 'dubox',
            'clienttype': '0',
            'shareid': metadata['shareid'],
            'type': 'dlink',
            'sign': metadata['sign'],
            'timestamp': metadata['timestamp'],
            'need_speed': '1',
            'jsToken': tokens['jsToken'],
            'bdstoken': tokens['bdstoken'],
            'dp-logid': tokens['logid']
        }

        body = {
            'product': 'share',
            'uk': metadata['uk'],
            'fid_list': json.dumps([file['fs_id']]),
            'primaryid': metadata['shareid']
        }

        url = f"https://www.terabox.com/share/download?{urlencode(query_params)}"
        parsed_url = urlparse(url)
        dynamic_headers = {
            **headers,
            'Host': parsed_url.hostname,
            'Referer': f"https://{parsed_url.hostname}/",
            'Origin': f"https://{parsed_url.hostname}"
        }
        print('[GET_FILE_DLINK] Request headers', {
            'Host': dynamic_headers['Host'],
            'Referer': dynamic_headers['Referer'],
            'Cookie': 'exists' if 'Cookie' in dynamic_headers else 'missing'
        })

        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=body, headers=dynamic_headers) as response:
                print('[GET_FILE_DLINK] Response received', {'status': response.status, 'url': str(response.url)})
                data = await response.json()
                print('[GET_FILE_DLINK] Response data', json.dumps(data, indent=2))

                dllink = data.get('dlink') or (data.get('list') or [{}])[0].get('dlink')
                print('[GET_FILE_DLINK] Extracted dlink', {'dllink': dllink})
                if not dllink:
                    raise Exception(data.get('errmsg', 'No download link in response'))

                print('[GET_FILE_DLINK] Following redirects for', {'filename': file['server_filename'], 'dllink': dllink})
                download_link = await follow_redirects(dllink, tokens)
                print('[GET_FILE_DLINK] Resolved download link', {'downloadLink': download_link})

                direct_link_parts = list(urlparse(download_link))
                direct_query = parse_qs(direct_link_parts[4])
                direct_query.update({
                    'sign': metadata['sign'],
                    'timestamp': metadata['timestamp'],
                    'jsToken': tokens['jsToken']
                })
                direct_link_parts[4] = urlencode(direct_query, doseq=True)
                final_link = urlunparse(direct_link_parts)

                result = {'downloadLink': final_link, 'dllink': dllink}
                print('[GET_FILE_DLINK] Returning result', result)
                return result
    except Exception as e:
        print('[GET_FILE_DLINK] Failed', {
            'filename': file['server_filename'],
            'message': str(e)
        })
        raise


# Assume headers is defined elsewhere
# headers = { ... }

async def follow_redirects(initial_url, tokens):
    logging.info('[FOLLOW_REDIRECTS] Starting', {
        'initialUrl': initial_url,
        'tokens': {
            'jsToken': bool(tokens.get('jsToken')),
            'logid': bool(tokens.get('logid')),
            'bdstoken': bool(tokens.get('bdstoken'))
        }
    })

    timeout = 15
    max_redirects = 5
    current_url = initial_url
    redirect_count = 0

    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            while redirect_count < max_redirects:
                logging.info('[FOLLOW_REDIRECTS] Attempt', {
                    'attempt': redirect_count + 1,
                    'maxRedirects': max_redirects,
                    'currentUrl': current_url
                })

                dynamic_headers = {
                    **headers,
                    "Host": urlparse(current_url).hostname,
                    "Referer": f"https://{urlparse(current_url).hostname}/",
                    "Origin": f"https://{urlparse(current_url).hostname}/"
                }

                logging.info('[FOLLOW_REDIRECTS] Request headers', {
                    'Host': dynamic_headers['Host'],
                    'Referer': dynamic_headers['Referer'],
                    'Cookie': 'exists' if 'Cookie' in dynamic_headers else 'missing'
                })

                async with session.get(current_url, headers=dynamic_headers, allow_redirects=False, ssl=ssl_context) as resp:
                    logging.info('[FOLLOW_REDIRECTS] Response received', {
                        'status': resp.status,
                        'url': str(resp.url),
                        'headers': dict(resp.headers)
                    })

                    if resp.status in (301, 302, 303, 307, 308):
                        location = resp.headers.get('Location')
                        logging.info('[FOLLOW_REDIRECTS] Location header', {'location': location})

                        if not location:
                            raise Exception('Redirect response missing Location header')

                        current_url = urljoin(current_url, location)
                        logging.info('[FOLLOW_REDIRECTS] New URL', {'currentUrl': current_url})

                        redirect_count += 1
                        await asyncio.sleep(1)
                        continue

                    if resp.status >= 400:
                        body = await resp.text()
                        logging.error('[FOLLOW_REDIRECTS] Error response', {
                            'status': resp.status,
                            'body': body
                        })
                        raise Exception(f"HTTP {resp.status}")

                    logging.info('[FOLLOW_REDIRECTS] Successfully resolved URL', {'resolvedUrl': current_url})
                    return str(current_url)

        raise Exception(f"Too many redirects (max {max_redirects} allowed)")

    except Exception as e:
        logging.error('[FOLLOW_REDIRECTS] Failed', {
            'message': str(e),
            'url': initial_url
        })
        raise

def error_response(status: int, message: str) -> JSONResponse:
    logging.error('[ERROR_RESPONSE] Creating error response', extra={'status': status, 'message': message})
    response = JSONResponse(
        status_code=status,
        content={"error": message},
        headers={"Access-Control-Allow-Origin": "*"}
    )
    logging.error('[ERROR_RESPONSE] Response sent', extra={'status': status, 'message': message})
    return response

def success_response(data: dict) -> JSONResponse:
    logging.info('[SUCCESS_RESPONSE] Creating success response', extra={
        'data': {
            'success': data.get('success'),
            'isFolder': data.get('isFolder'),
            'dataLength': len(data.get('data', []))
        }
    })
    response = JSONResponse(
        status_code=200,
        content=data,
        headers={
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
        }
    )
    logging.info('[SUCCESS_RESPONSE] Response sent', extra={
        'status': 200,
        'dataLength': len(data.get('data', []))
    })
    return response

async def fetch_page(url: str, headers: dict) -> dict:
    logging.info('[FETCH_PAGE] Starting', {'url': url})
    max_redirects = 5
    redirect_count = 0
    current_url = url

    async with httpx.AsyncClient(follow_redirects=False, timeout=10) as client:
        while redirect_count < max_redirects:
            dynamic_headers = {
                **headers,
                "Host": httpx.URL(current_url).host,
                "Referer": f"https://{httpx.URL(current_url).host}/",
                "Origin": f"https://{httpx.URL(current_url).host}"
            }

            logging.info('[FETCH_PAGE] Request headers', {
                "Host": dynamic_headers["Host"],
                "Referer": dynamic_headers["Referer"],
                "Cookie": 'exists' if 'Cookie' in dynamic_headers else 'missing'
            })

            response = await client.get(current_url, headers=dynamic_headers)
            logging.info('[FETCH_PAGE] Response', {
                "status": response.status_code,
                "url": str(response.url),
                "headers": dict(response.headers)
            })

            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get("location")
                if not location:
                    raise Exception("Redirect response missing Location header")
                current_url = str(httpx.URL(location, base=current_url))
                logging.info('[FETCH_PAGE] Redirecting to', {'current_url': current_url})
                redirect_count += 1
                await asyncio.sleep(1)
                continue
            break

        if redirect_count >= max_redirects:
            raise Exception(f"Too many redirects (max {max_redirects} allowed)")

        final_headers = {
            **headers,
            "Host": httpx.URL(current_url).host,
            "Referer": f"https://{httpx.URL(current_url).host}/",
            "Origin": f"https://{httpx.URL(current_url).host}"
        }

        response = await client.get(current_url, headers=final_headers)
        logging.info('[FETCH_PAGE] Final response', {
            "status": response.status_code,
            "url": str(response.url),
            "headers": dict(response.headers)
        })

        html = response.text
        logging.info('[FETCH_PAGE] Returning result', {
            "finalUrl": str(response.url),
            "htmlLength": len(html)
        })
        return {"html": html, "finalUrl": str(response.url)}

async def getFileMetadata(surl: str, headers: dict) -> dict:
    logging.info('[GET_FILE_METADATA] Starting', {'surl': surl})
    url = f"https://www.1024tera.com/api/shorturlinfo?app_id=250528&shorturl={surl}&root=1"
    max_retries = 3
    timeout = 10  # seconds

    for attempt in range(1, max_retries + 1):
        try:
            dynamic_headers = {
                **headers,
                "Host": httpx.URL(url).host,
                "Referer": f"https://{httpx.URL(url).host}/",
                "Origin": f"https://{httpx.URL(url).host}"
            }

            logging.info(f'[GET_FILE_METADATA] Attempt {attempt} - Request headers', {
                "Host": dynamic_headers["Host"],
                "Referer": dynamic_headers["Referer"],
                "Cookie": 'exists' if 'Cookie' in dynamic_headers else 'missing'
            })

            async with httpx.AsyncClient(timeout=timeout) as client:
                response = await client.get(url, headers=dynamic_headers)

            logging.info('[GET_FILE_METADATA] Response received', {
                "status": response.status_code,
                "url": str(response.url)
            })

            data = response.json()
            logging.info('[GET_FILE_METADATA] Response data', data)

            if not data or data.get("errno") != 0:
                logging.error('[GET_FILE_METADATA] API error', {
                    "errno": data.get("errno"),
                    "errmsg": data.get("errmsg")
                })
                raise Exception(data.get("errmsg", "Invalid metadata response"))

            logging.info('[GET_FILE_METADATA] Returning metadata', {
                "listLength": len(data.get("list", [])),
                "shareid": data.get("shareid"),
                "uk": data.get("uk")
            })
            return data

        except httpx.RequestError as e:
            logging.warning(f'[GET_FILE_METADATA] Attempt {attempt} failed: {e}')
        except Exception as e:
            logging.warning(f'[GET_FILE_METADATA] Attempt {attempt} error: {str(e)}')

        if attempt == max_retries:
            logging.error('[GET_FILE_METADATA] All attempts failed', {
                "message": str(e)
            })
            raise

        await asyncio.sleep(attempt)  # Exponential backoff

def is_video(filename):
    print('[IS_VIDEO] Checking:', filename)
    pattern = r'\.(mp4|mkv|avi|mov|wmv|flv|webm|m3u8|ts)$'
    result = re.search(pattern, filename, re.IGNORECASE) is not None
    print('[IS_VIDEO] Result:', {'filename': filename, 'is_video': result})
    return result

def format_size(bytes_):
    print('[FORMAT_SIZE] Starting:', {'bytes': bytes_})
    if not bytes_:
        print('[FORMAT_SIZE] Returning for zero bytes:', {'result': '0 B'})
        return '0 B'
    
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    size = float(bytes_)
    i = 0
    while size >= 1024 and i < len(units) - 1:
        size /= 1024
        i += 1
    result = f"{size:.2f} {units[i]}"
    print('[FORMAT_SIZE] Returning:', {'result': result})
    return result


log = logging.getLogger("extractLogid")

async def extractLogid(html: str, listsurl: str, jsToken: str, metadata: dict, headers: dict) -> str:
    log.info('[EXTRACT_LOGID] Starting', extra={
        "listsurl": listsurl,
        "jsToken": bool(jsToken),
        "htmlLength": len(html),
        "metadata": {
            "shareid": metadata.get("shareid"),
            "isdir": metadata.get("list", [{}])[0].get("isdir")
        }
    })

    patterns = [
        re.compile(r'dp-logid=([^&]+)'),
        re.compile(r'"dp-logid"\s*:\s*"([^"]+)"'),
        re.compile(r'dp-logid\s*=\s*[\'"]([^\'"]+)[\'"]'),
        re.compile(r'logid=([^&]+)')
    ]

    # 1. Check HTML directly
    for pattern in patterns:
        match = pattern.search(html)
        if match and re.fullmatch(r'[0-9a-zA-Z]+', match[1]):
            log.info('[EXTRACT_LOGID] Logid from HTML', extra={"logid": match[1], "pattern": pattern.pattern})
            return match[1]

    log.warning('[EXTRACT_LOGID] No logid found in HTML')

    is_folder = metadata.get("list", [{}])[0].get("isdir") == 1
    log.info('[EXTRACT_LOGID] Share type', extra={"isFolder": is_folder})

    try:
        async with aiohttp.ClientSession() as session:
            if is_folder:
                dir_path = metadata["list"][0].get("path", "/")
                root = 1 if dir_path == "/" else 0
                folder_url = (
                    f"https://www.1024tera.com/share/list?app_id=250528&web=1&jsToken={quote(jsToken)}"
                    f"&page=1&num=1&by=name&order=asc&shorturl={quote(listsurl)}&root={root}&dir={quote(dir_path)}"
                )
                parsed = urlparse(folder_url)
                folder_headers = headers.copy()
                folder_headers.update({
                    "Host": parsed.hostname,
                    "Referer": f"https://{parsed.hostname}/",
                    "Origin": f"https://{parsed.hostname}/"
                })
                async with session.get(folder_url, headers=folder_headers) as resp:
                    log.info('[EXTRACT_LOGID] Folder response', extra={
                        "status": resp.status,
                        "url": str(resp.url),
                        "headers": dict(resp.headers)
                    })
                    folder_html = await resp.text()
                    for pattern in patterns:
                        match = pattern.search(folder_html)
                        if match and re.fullmatch(r'[0-9a-zA-Z]+', match[1]):
                            log.info('[EXTRACT_LOGID] Logid from folder HTML', extra={"logid": match[1], "pattern": pattern.pattern})
                            return match[1]

            else:
                file_url = (
                    f"https://www.1024tera.com/share/list?app_id=250528&web=1&jsToken={quote(jsToken)}"
                    f"&page=1&num=1&by=name&order=asc&shorturl={quote(listsurl)}&root=1"
                    f"&shareid={metadata['shareid']}&uk={metadata['uk']}"
                )
                parsed = urlparse(file_url)
                file_headers = headers.copy()
                file_headers.update({
                    "Host": parsed.hostname,
                    "Referer": f"https://{parsed.hostname}/",
                    "Origin": f"https://{parsed.hostname}/"
                })
                async with session.get(file_url, headers=file_headers) as resp:
                    log.info('[EXTRACT_LOGID] File response', extra={
                        "status": resp.status,
                        "url": str(resp.url),
                        "headers": dict(resp.headers)
                    })
                    try:
                        json_data = await resp.json()
                    except Exception:
                        json_text = await resp.text()
                        raise Exception(f"Failed to parse JSON, got: {json_text[:300]}")

                    log.debug('[EXTRACT_LOGID] File response data', extra={"json": json_data})

                    logid_candidates = [
                        json_data.get("dp_logid"),
                        json_data.get("logid")
                    ]
                    for logid in logid_candidates:
                        if logid and re.fullmatch(r'[0-9a-zA-Z]+', logid):
                            log.info('[EXTRACT_LOGID] Logid from JSON body', extra={"logid": logid})
                            return logid

                    entry = json_data.get("list", [{}])[0]
                    for key in ["dlink", "thumbs", "docpreview"]:
                        value = entry.get(key)
                        if isinstance(value, dict):
                            value = value.get("url1")
                        if isinstance(value, str):
                            match = re.search(r'dp-logid=([^&]+)', value)
                            if match and re.fullmatch(r'[0-9a-zA-Z]+', match[1]):
                                log.info('[EXTRACT_LOGID] Logid from key %s', key, extra={"logid": match[1]})
                                return match[1]

                    location = resp.headers.get("location")
                    if location:
                        match = re.search(r'dp-logid=([^&]+)', location)
                        if match and re.fullmatch(r'[0-9a-zA-Z]+', match[1]):
                            log.info('[EXTRACT_LOGID] Logid from redirect header', extra={"logid": match[1]})
                            return match[1]

    except Exception as e:
        log.exception('[EXTRACT_LOGID] Error during logid extraction')
        raise Exception("Failed to extract dp-logid. Possibly due to expired cookies or invalid share link.") from e

    raise Exception("Missing dp-logid. Check share link, cookies, or API changes.")

def get_surl(url: str):
    print('[GET_SURL] Starting', {'url': url})
    try:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        surl = qs.get('surl', [None])[0] or url.rstrip('/').split('/')[-1]
        print('[GET_SURL] Extracted surl', {'surl': surl})
        return surl
    except Exception as e:
        print('[GET_SURL] Failed', {'message': str(e)})
        return None

def extract_between(s: str, start: str, end: str):
    start_idx = s.find(start)
    if start_idx == -1:
        return None
    end_idx = s.find(end, start_idx + len(start))
    if end_idx == -1:
        return None
    return s[start_idx + len(start):end_idx].strip()

def extract_initial_state(html: str):
    print('[EXTRACT_INITIAL_STATE] Starting', {'htmlLength': len(html)})
    try:
        match = re.search(r'window\.__INITIAL_STATE__\s*=\s*(\{[\s\S]*?\})\s*;', html)
        print('[EXTRACT_INITIAL_STATE] Regex match', {'hasMatch': bool(match)})
        if not match:
            print('[EXTRACT_INITIAL_STATE] No initial state found')
            return {'state': None, 'bdstoken': None}
        result = json.loads(match.group(1))
        bdstoken = result.get('bdstoken')
        # Fallback: check if bdstoken is inside yunData
        if not bdstoken and result.get('yunData', {}).get('bdstoken'):
            bdstoken = result['yunData']['bdstoken']
        print('[EXTRACT_INITIAL_STATE] Parsed', {
            'hasBdstoken': bool(bdstoken),
            'keys': list(result.keys())
        })
        return {'state': result, 'bdstoken': bdstoken}
    except Exception as e:
        print('[EXTRACT_INITIAL_STATE] Failed', {'message': str(e)})
        return {'state': None, 'bdstoken': None}

def extract_js_token(html: str):
    print('[EXTRACT_JS_TOKEN] Starting', {'htmlLength': len(html)})
    patterns = [
        {'start': 'fn%28%22', 'end': '%22%29'},
        {'start': 'jsToken":"', 'end': '"'},
        {'start': '"token":"', 'end': '"'},
        {'start': 'yunData.token = "', 'end': '"'},
        {'start': 'bdstoken":"', 'end': '"'}
    ]
    for pattern in patterns:
        js_token = extract_between(html, pattern['start'], pattern['end'])
        if is_valid_token(js_token):
            print('[EXTRACT_JS_TOKEN] Token found using pattern', {'jsToken': js_token, 'pattern': pattern['start']})
            return js_token
    print('[EXTRACT_JS_TOKEN] No token matched')
    return None

def extract_bdstoken(html: str):
    print('[EXTRACT_BDSTOKEN] Starting')

    try:
        # Attempt 1: Extract from yunData
        yun_data_match = re.search(r'var\s+yunData\s*=\s*(\{[\s\S]*?\});', html)
        if yun_data_match:
            raw = yun_data_match.group(1)
            fixed = fix_json(raw)
            try:
                yun_data = json.loads(fixed)
                token = yun_data.get('bdstoken') or yun_data.get('token')
                if is_valid_token(token):
                    print('[EXTRACT_BDSTOKEN] Found in yunData:', token)
                    return token
            except Exception:
                print('[EXTRACT_BDSTOKEN] Failed to parse yunData JSON')

        # Attempt 2: Regex patterns
        regexes = [
            re.compile(r'["\']?bdstoken["\']?\s*[:=]\s*["\']([a-fA-F0-9]{8,})["\']'),
            re.compile(r'["\']?token["\']?\s*[:=]\s*["\']([a-fA-F0-9]{8,})["\']'),
            re.compile(r'bdstoken=([a-fA-F0-9]{8,})')
        ]

        for regex in regexes:
            match = regex.search(html)
            if match and is_valid_token(match.group(1)):
                print('[EXTRACT_BDSTOKEN] Found with fallback regex:', match.group(1))
                return match.group(1)

        # Attempt 3: From thumbnail URLs or query params
        thumb_match = re.search(r'bdstoken=([a-fA-F0-9]{8,})', html)
        if thumb_match and is_valid_token(thumb_match.group(1)):
            print('[EXTRACT_BDSTOKEN] Found in thumbnail URL:', thumb_match.group(1))
            return thumb_match.group(1)

        print('[EXTRACT_BDSTOKEN] No bdstoken found')
        return None

    except Exception as e:
        print('[EXTRACT_BDSTOKEN] Error:', str(e))
        return None

def extract_tokens(html: str):
    print('[EXTRACT_TOKENS] Starting', {'htmlLength': len(html)})

    try:
        result = extract_initial_state(html)
        initial_state = result['state']
        initial_bdstoken = result['bdstoken']

        print('[EXTRACT_TOKENS] Initial state parsed', {'hasInitialState': bool(initial_state)})

        js_token = extract_js_token(html)
        bdstoken = initial_bdstoken or extract_bdstoken(html)

        if not js_token or not bdstoken:
            print('[EXTRACT_TOKENS] Missing token(s)', {'jsToken': js_token, 'bdstoken': bdstoken})
            raise ValueError('Token extraction failed: Missing jsToken or bdstoken')

        print('[EXTRACT_TOKENS] Tokens extracted successfully', {
            'jsTokenPreview': js_token[:6] + '...' if js_token else None,
            'bdstokenPreview': bdstoken[:6] + '...' if bdstoken else None
        })

        return {'jsToken': js_token, 'bdstoken': bdstoken}

    except Exception as e:
        print('[EXTRACT_TOKENS] Failed', {'message': str(e)})
        return {'jsToken': None, 'bdstoken': None}

def fix_json(js_obj_str: str):
    # Replace unquoted keys with quoted keys.
    fixed = re.sub(r'([{,])(\s*)([a-zA-Z0-9_]+)\s*:', r'\1"\3":', js_obj_str)
    # Remove trailing commas before closing braces.
    fixed = re.sub(r',\s*}', '}', fixed)
    return fixed

def is_valid_token(token):
    return isinstance(token, str) and len(token) >= 8 and re.fullmatch(r'[a-fA-F0-9]+', token) is not None



# your route definitions here...

if __name__ == "__main__":

    port = int(os.environ.get("PORT", PORT))
    uvicorn.run("index:app", host="0.0.0.0", port=port, reload=True)

