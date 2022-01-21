import json
import re

import flask
import requests
from flask import Flask, make_response

app = Flask(__name__)
IP_REGEX = r"((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][" \
           r"0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[" \
           r"0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([" \
           r"0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[" \
           r"0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1," \
           r"4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1," \
           r"4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[" \
           r"0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1," \
           r"5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){" \
           r"3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[" \
           r"0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1," \
           r"7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){" \
           r"3}))|:)))(%.+)?\s*$))"

FIELDS = [
    "continent",
    "continentCode",
    "country",
    "countryCode",
    "region",
    "regionName",
    "city",
    "zip",
    "lat",
    "lon",
    "timezone",
    "offset",
    "currency",
    "isp",
    "org",
    "as",
    "asname",
    "reverse",
    "mobile",
    "proxy",
    "hosting",
    'status',
    'message',
    'query',
    'district'
]

LANGUAGES = [
    "en",
    "pt-BR",
    "de",
    "fr",
    "ja",
    "zh-CN",
    "ru"
]

MANDATORY_RESPONSE_HEADERS = [
    "X-Rl",
    "X-Ttl",
    "Content-Type"
]

GET_PARAM = {
    "fields": {
        "list": FIELDS,
        "multiple": True,
        "separator": ','
    },
    "lang": {
        "list": LANGUAGES,
        "multiple": False,
        "seperator": None
    },
    "callback": None
}

URL = "http://ip-api.com/json/{ip}"

IP_PROG = re.compile(IP_REGEX)


@app.route('/json', methods=['POST', 'GET'])
@app.route('/json/<ip>', methods=['POST', 'GET'])
def get_json(ip: str = None):
    match_reg: [bool, None] = False

    print(flask.request.environ)

    if ip is None or len(ip) == 0:
        if 'HTTP_X_FORWARDED_FOR' in flask.request.environ:
            ip = flask.request.environ['HTTP_X_FORWARDED_FOR']
        elif 'REMOTE_ADDR' in flask.request.environ:
            ip = flask.request.environ['REMOTE_ADDR']
        else:
            ip = flask.request.remote_addr

    if ip is None or len(ip) == 0:
        return 'Bad Request Error', 400

    ip = str(ip)
    match_reg = IP_PROG.match(string=ip)

    if match_reg is None:
        match_reg = False

    if isinstance(match_reg, re.Match):
        match_reg = True

    if not match_reg:
        response = make_response("<h1 style=\"margin:0;margin-bottom: 1rem;\">Internal Server Error!!</h1><p>The server encountered an internal server error while fetching your request.</p>")
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Content-Type'] = 'text/html'
        return response, 400

    request_url = URL.format(ip=ip)
    query_list = {}

    for a in flask.request.args.keys():
        if a not in GET_PARAM.keys():
            response = make_response("<h1 style=\"margin:0;margin-bottom: 1rem;\">Bad Request!!</h1><code>{}</code> "
                                     "is not a valid query.".format(a))
            response.headers['Access-Control-Allow-Origin'] = '*'
            response.headers['Content-Type'] = 'text/html'
            return response, 400
        else:
            query = flask.request.args.get(a)
            query_bounds = GET_PARAM[a]
            if query_bounds is not None:
                if query_bounds['multiple'] is True:
                    query = query.split(query_bounds['separator'])
                else:
                    query = list(query)

                for q in query:
                    if q not in query_bounds['list']:
                        response = make_response(
                            "<h1 style=\"margin:0;margin-bottom: 1rem;\">Bad Request!!</h1><code>{} = {}</code> "
                            "is not valid".format(a, q))
                        response.headers['Access-Control-Allow-Origin'] = '*'
                        response.headers['Content-Type'] = 'text/html'
                        return response, 400

                query_list[a] = flask.request.args.get(a)
    request_url = URL.format(ip=ip)

    if len(query_list) != 0:
        query_append = []
        for k, v in query_list.items():
            query_append.append("{}={}".format(k, v))
        if len(query_append) != 0:
            query_append = '&'.join(query_append)
            request_url = request_url + "?" + query_append

    response_from_request = requests.get(request_url)
    response: [flask.Response, None] = None
    status_code = 200

    if response_from_request.status_code == 200:
        response = make_response(json.dumps(json.loads(response_from_request.content), indent=1))
        status_code = 200
    elif response_from_request.status_code == 429:
        status_code = 429
        response = make_response("Too many requests.")

    if response_from_request.status_code == 200 or response_from_request.status_code == 429:
        for header_name in MANDATORY_RESPONSE_HEADERS:
            if header_name in response_from_request.headers:
                response.headers[header_name] = response_from_request.headers[header_name]
    
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response, status_code


if __name__ == '__main__':
    app.run(threaded=True, port=5000)
