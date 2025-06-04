from fastapi import FastAPI, Request, Response, Query
from fastapi.responses import JSONResponse
import aiohttp
import logging
import json
from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

app = FastAPI()

import logging

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
        result = await process_terabox_share(url)
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

async def process_list_data(file_list, metadata, tokens):
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
