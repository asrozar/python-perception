import httplib
import json
import syslog
import requests

headers = {'Accept': 'text/plain',
           'Content-type': 'application/json'}


class Elasticsearch(object):
    def __init__(self, es_host, es_port, doc_index, doc_type, doc_id, doc, source, size, query):
        self.es_host = es_host,
        self.es_port = es_port,
        self.doc_index = doc_index,
        self.doc_type = doc_type,
        self.doc_id = doc_id,
        self.doc = doc
        self.source = source,
        self.size = size
        self.query = query

        self.search_documents(es_host, es_port, doc_index, doc_type, source, size, query)
        self.add_document(es_host, es_port, doc_index, doc_type, doc_id, doc)

    @staticmethod
    def search_documents(es_host, es_port, doc_index, doc_type, source, size, query):

        if doc_type is None:
            url = 'http://%s:%s/%s/_search/' % (es_host, es_port, doc_index)

        else:
            url = 'http://%s:%s/%s/%s/_search/' % (es_host, es_port, doc_index, doc_type)

        if size is None:
            size = 10000

        if query is None:
            query = '{ "match_all" : {} } }'

        if source:
            body = '{ "_source": true, "size": %s, "query": %s' % (size, query)

        elif source is False:
            body = '{ "_source": false, "size": %s, "query": %s' % (size, query)

        else:
            body = '{ "_source": "%s", "size": %s, "query": %s' % (source, size, query)

        resp = requests.get(url=url, headers=headers, data=body)

        if resp.status_code == 200:
            return resp.json()

        elif resp.status_code == 400:
            syslog.syslog(syslog.LOG_INFO, str(resp.json()))
            return 99

        elif resp.status_code == 403:
            syslog.syslog(syslog.LOG_INFO, str(resp.json()))
            return 99

        elif resp.status_code == 404:
            syslog.syslog(syslog.LOG_INFO, str(resp.json()))
            return 99

        elif resp.status_code == 409:
            syslog.syslog(syslog.LOG_INFO, str(resp.json()))
            return 99

        elif resp.status_code == 412:
            syslog.syslog(syslog.LOG_INFO, str(resp.json()))
            return 99

        elif resp.status_code == 500:
            syslog.syslog(syslog.LOG_INFO, str(resp.json()))
            return 99

        elif resp.status_code == 503:
            syslog.syslog(syslog.LOG_INFO, str(resp.json()))
            return 99

    @staticmethod
    def get_document(es_host, es_port, doc_index, doc_type, doc_id):
        try:
            url = 'http://%s:%s/%s/%s/%s/' % (es_host, es_port, doc_index, doc_type, doc_id)
            resp = requests.get(url=url, headers=headers)

            if resp.status_code == 200:
                return resp.json()

            elif resp.status_code == 400:
                syslog.syslog(syslog.LOG_INFO, str(resp.json()))
                return 99

            elif resp.status_code == 403:
                syslog.syslog(syslog.LOG_INFO, str(resp.json()))
                return 99

            elif resp.status_code == 404:
                syslog.syslog(syslog.LOG_INFO, str(resp.json()))
                return 99

            elif resp.status_code == 409:
                syslog.syslog(syslog.LOG_INFO, str(resp.json()))
                return 99

            elif resp.status_code == 412:
                syslog.syslog(syslog.LOG_INFO, str(resp.json()))
                return 99

            elif resp.status_code == 500:
                syslog.syslog(syslog.LOG_INFO, str(resp.json()))
                return 99

            elif resp.status_code == 503:
                syslog.syslog(syslog.LOG_INFO, str(resp.json()))
                return 99

        except Exception as get_document_e:
            syslog.syslog(syslog.LOG_INFO, 'es_add_document error: %s' % str(get_document_e))

    @staticmethod
    def add_document(es_host, es_port, doc_index, doc_type, doc_id, doc):

        try:

            conn = httplib.HTTPConnection(es_host,
                                          es_port)

            if doc_id is None:
                conn.request('POST', '/%s/%s?' % (doc_index,
                                                  doc_type),
                             headers=headers,
                             body=doc)

            elif doc_id is not None:
                conn.request('PUT', '/%s/%s/%s?' % (doc_index,
                                                    doc_type,
                                                    doc_id),
                             headers=headers,
                             body=doc)

            resp = conn.getresponse()
            data = resp.read()

            json_resp = json.loads(data)

            if resp.status == 400:
                syslog.syslog(syslog.LOG_INFO, str(json_resp))

            elif resp.status == 403:
                syslog.syslog(syslog.LOG_INFO, str(json_resp))

            elif resp.status == 404:
                syslog.syslog(syslog.LOG_INFO, str(json_resp))

            elif resp.status == 409:
                syslog.syslog(syslog.LOG_INFO, str(json_resp))

            elif resp.status == 412:
                syslog.syslog(syslog.LOG_INFO, str(json_resp))

            elif resp.status == 500:
                syslog.syslog(syslog.LOG_INFO, str(json_resp))

            elif resp.status == 503:
                syslog.syslog(syslog.LOG_INFO, str(json_resp))

        except Exception as es_add_data_e:
            syslog.syslog(syslog.LOG_INFO, 'es_add_document error: %s' % str(es_add_data_e))
            syslog.syslog(syslog.LOG_INFO, 'es_add_document event: %s' % str(str(doc)))
