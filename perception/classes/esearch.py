import httplib
import json
import syslog


class Elasticsearch(object):
    def __init__(self, es_host, es_port, doc_index, doc_type, doc_id, doc):
        self.es_host = es_host,
        self.es_port = es_port,
        self.doc_index = doc_index,
        self.doc_type = doc_type,
        self.doc_id = doc_id,
        self.doc = doc

        self.add_document(es_host, es_port, doc_index, doc_type, doc_id, doc)

    @staticmethod
    def add_document(es_host, es_port, doc_index, doc_type, doc_id, doc):

        try:
            headers = {'Accept': 'text/plain',
                       'Content-type': 'application/json'}

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
