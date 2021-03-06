import json
from oauth2client.client import AccessTokenCredentials
import flask
import httplib2
import base64
from apiclient import discovery, errors
from html.parser import HTMLParser
from httplib2 import Http
from bs4 import BeautifulSoup
import re
import time
import dateutil.parser as parser
from datetime import datetime
import datetime
from flask import Flask, render_template, request, jsonify, make_response
from oauth2client.client import AccessTokenCredentials

from normalization import normalize_corpus
from utils import build_feature_matrix
import numpy as np
import pandas
import requests
from googleapiclient.errors import HttpError
from contextlib import contextmanager
from functools import partial
from nltk.stem import PorterStemmer
import multiprocessing

parserr = HTMLParser()
ps = PorterStemmer()


user_id =  'me'
label_id_one = 'INBOX'
label_id_two = 'UNREAD'

tasks = [
    {
        'id': 1,
        'text': u'Schedule a meeting',
        'intent': u'schedule',




    },
    {
        'id': 2,
        'text': u'asdad',
        'intent': u'None', 


    }
]

# Create an instance of class "Flask" with name of running application as the arg
app = Flask(__name__)



@contextmanager
def poolcontext(*args, **kwargs):
    pool = multiprocessing.Pool(*args, **kwargs)
    yield pool
    pool.terminate()

def new(m_id,b,c):
    temp_dict = { } 
    #http = Http()
    #credentials = AccessTokenCredentials(t, 'user-agent-value')
    #http_auth = credentials.authorize(http)
    #GMAIL = discovery.build('gmail', 'v1', http=http_auth)
    http = Http()
    credentials = AccessTokenCredentials(b, 'user-agent-value')
    http_auth = credentials.authorize(http)
    GMAIL = discovery.build('gmail', 'v1', http=http)
    message = GMAIL.users().messages().get(userId=user_id, id=m_id).execute() # fetch the message using API
    print('message is')
    print(message)
    payld = message['payload'] # get payload of the message 
    headr = payld['headers'] # get header of the payload
    temp_dict['id']=message['id']
    temp_dict['threadId']=message['threadId']
    
    for six in headr:
        if six['name']=='Sender':
            temp_dict['Rem_Send'] = six['value']
        else:
            pass
         

    for one in headr: # getting the Subject
        if one['name'] == 'Subject':
            msg_subject = one['value']
            temp_dict['Subject'] = msg_subject
        else:
            pass
    for two in headr: # getting the date
        if two['name'] == 'Date':
            msg_date = two['value']
            date_parse = (parser.parse(msg_date))
            new_date=str(date_parse)
            new_date=new_date.replace(' ', 'T' )
            m_date = (date_parse.date())
            temp_dict['Date'] = new_date
        else:
            pass
    for three in headr: # getting the Sender
        if three['name'] == 'From':
            msg_from = three['value']
            temp_dict['Sender'] = msg_from
        else:
            pass
    for four in headr: # getting the Sender
        if four['name'] == 'To':
            msg_to = four['value']
            temp_dict['To'] = msg_to.split(',')
        else:
            pass
    for five in headr:
        if five['name'] == 'Cc':
            msg_cc = five['value']
            temp_dict['Cc'] = msg_cc.split(',')
        else:
            pass

        tt=c.unescape(message['snippet'])
        temp_dict['Snippet']=tt

    temp_dict['labelIds']=message['labelIds'] 
    '''
    try:
        try:
            mssg_parts = payld['parts'][0]['body']['data']
        except:
            mssg_parts = payld['parts'][0]['parts']['0']['body']['data']
        #clean_one = part_data.replace("-","+")
        #clean_one = clean_one.replace("_","/")
        #clean_two = base64.b64decode (bytes(clean_one,'utf-8'))
        #soup = BeautifulSoup(clean_two , "html" )
        #m=soup.get_text()
        #mm=c.unescape(m)
        #sou = BeautifulSoup(mm , "lxml" )
        #mssg_body = sou.body()
        temp_dict['Message_body'] = base64.urlsafe_b64decode(mssg_parts)
    except:
        pass
    '''
    if 'Cc' not in temp_dict.keys():
        temp_dict['Cc'] = []

    return temp_dict


def get_message(service,querry,user_id,label_id_one,token):
    response = service.users().messages().list(userId=user_id,labelIds=[label_id_one],q=querry).execute()
    messages = []
    if 'messages' in response:
        messages.extend(response['messages'])
    while 'nextPageToken' in response:
        page_token = response['nextPageToken']
        response = service.users().messages().list(userId=user_id, labelIds=[label_id_one],q=querry,pageToken=page_token).execute()
        messages.extend(response['messages'])
    
    final_list = [ ]
    names=[]
    for mss in messages:
        names.append(mss['id'])
    print(len(names))
    print('start')
    with poolcontext(processes=45) as pool:
        final_list = pool.map(partial(new, b=token,c=parserr), names)
    return final_list


def email_cleanup(email):
    """
    Cleaning up raw text of emails
    """
    email = email.replace('\n', " ").lower()
    email = email.replace('\n', " ")

    patterns = [
    r"from: (\w+), (\w+) (\w+)?",
    r"(date):? \d+/\d+/\d+",
    r"case no. \w-\d+-\d+",
    r"[0-2]?[0-9]:[0-6][0-9] (am|pm)",
    r"(sent|updated)?:? (monday|tuesday|wednesday|thursday|friday|saturday|sunday), (january|february|march|april|may|june|july|august|september|october|november|december) \d+, \d{4} \d{0,2}:\d{0,2} (am|pm)",
    r"[\w]+@[\.\w]+",
    r"(monday|tuesday|wednesday|thursday|friday|saturday|sunday)",
    r"january|february|march|april|may|june|july|august|september|october|november|december",
    r"doc no. \w?\d+",
    r"state dept. - produced to house select benghazi comm.",
    r"subject to agreement on sensitive information & redactions.",
    r"no foia waiver.",
    r"[\@!<>()&-:';]",
    ]
    
    for pattern in patterns:
        email = re.sub(pattern, " ", email)
    email = re.sub('\s+', ' ', email)       #ye part smjhna hh
    email = email.encode('ascii', 'ignore')     
    email = email.decode()
    return email

def compute_cosine_similarity(doc_features, corpus_features):
    # get document vectors
    doc_features = doc_features[0]
    # compute similarities
    similarity = np.dot(doc_features,corpus_features.T)
    similarity = similarity.toarray()[0]
    # get docs with highest similarity scores
    top_docs = similarity.argsort()[::-1]
    top_docs_with_score = [(index, round(similarity[index], 3))  for index in top_docs]

    return top_docs_with_score

import requests
import uuid
import json

graph_endpoint = 'https://graph.microsoft.com/v1.0{0}'

# Generic API Sending
def make_api_call(method, url, token, user_email, payload = None, parameters = None):
    headers = { 'User-Agent' : 'python_tutorial/1.0',
              'Authorization' : 'Bearer {0}'.format(token),
              'Accept' : 'application/json',
              'X-AnchorMailbox' : user_email }
    request_id = str(uuid.uuid4())
    instrumentation = { 'client-request-id' : request_id,
                      'return-client-request-id' : 'true' }
    headers.update(instrumentation)
    response = None
    if (method.upper() == 'GET'):
        response = requests.get(url, headers = headers, params = parameters)
    elif (method.upper() == 'DELETE'):
        response = requests.delete(url, headers = headers, params = parameters)
    elif (method.upper() == 'PATCH'):
        headers.update({ 'Content-Type' : 'application/json' })
        response = requests.patch(url, headers = headers, data = json.dumps(payload), params = parameters)
    elif (method.upper() == 'POST'):
        headers.update({ 'Content-Type' : 'application/json' })
        response = requests.post(url, headers = headers, data = json.dumps(payload), params = parameters)
    return response

def get_me(access_token):
    get_me_url = graph_endpoint.format('/me')
    query_parameters = {'$select': 'displayName,mail'}
    r = make_api_call('GET', get_me_url, access_token, "", parameters = query_parameters)

    if (r.status_code == requests.codes.ok):
        return r.json()
    else:
        return "{0}: {1}".format(r.status_code, r.text)


def get_my_messages(access_token, user_email):
    get_messages_url = graph_endpoint.format('/me/mailfolders/inbox/messages')

    # Use OData query parameters to control the results
    #  - Only first 10 results returned
    #  - Only return the ReceivedDateTime, Subject, and From fields
    #  - Sort the results by the ReceivedDateTime field in descending order
    query_parameters = {#'$top': '10',
                      '$select': 'receivedDateTime,subject,from',
                      '$orderby': 'receivedDateTime DESC'}

    r = make_api_call('GET', get_messages_url, access_token, user_email, parameters = query_parameters)

    if (r.status_code == requests.codes.ok):
        return r.json()
    else:
        return "{0}: {1}".format(r.status_code, r.text)

def get_my_events(access_token, user_email):
    get_events_url = graph_endpoint.format('/me/events')

    # Use OData query parameters to control the results
    #  - Only first 10 results returned
    #  - Only return the Subject, Start, and End fields
    #  - Sort the results by the Start field in ascending order
    query_parameters = {'$top': '10',
                      '$select': 'subject,start,end',
                      '$orderby': 'start/dateTime ASC'}

    r = make_api_call('GET', get_events_url, access_token, user_email, parameters = query_parameters)

    if (r.status_code == requests.codes.ok):
        return r.json()
    else:
        return "{0}: {1}".format(r.status_code, r.text)


def filter_my_messages(access_token, user_email,search):
    get_messages_url = graph_endpoint.format('/me/mailfolders/inbox/messages')
    query_parameters = {
                      '$top' : '100',
                      '$search': '"{}"'.format(search),
                      '$select':'receivedDateTime,subject,from,bodyPreview,body,conversationId,toRecipients,ccRecipients',
                      }
    r = make_api_call('GET', get_messages_url, access_token, user_email, parameters = query_parameters)
    print(r.json())
    if (r.status_code == requests.codes.ok):
        return r.json()
    else:
        return "{0}: {1}".format(r.status_code, r.text)



def get_messages_byid(access_token, user_email,id):
    get_messages_url = graph_endpoint.format('/me/mailfolders/inbox/messages/{}'.format(id))

    # Use OData query parameters to control the results
    #  - Only first 10 results returned
    #  - Only return the ReceivedDateTime, Subject, and From fields
    #  - Sort the results by the ReceivedDateTime field in descending order
    query_parameters = {'$select':'receivedDateTime,subject,from,bodyPreview,conversationId,toRecipients,ccRecipients',
                      '$orderby': 'receivedDateTime DESC'}

    r = make_api_call('GET', get_messages_url, access_token, user_email, parameters = query_parameters)

    if (r.status_code == requests.codes.ok):
        return r.json()
    else:
        return "{0}: {1}".format(r.status_code, r.text)

def get_messages_byCid(access_token, user_email,Cid):

    get_messages_url = graph_endpoint.format('/me/messages/')

    query_parameters = {'$select': 'receivedDateTime,subject,from,body,bodyPreview',
                    '$filter': "conversationId eq '{}'".format(Cid),

                      }

    r = make_api_call('GET', get_messages_url, access_token, user_email, parameters = query_parameters)

    if (r.status_code == requests.codes.ok):
        return r.json()
    else:
        return "{0}: {1}".format(r.status_code, r.text)



    
# REST API: POST Request
@app.route('/api/post/related', methods=['GET','POST'])
def related():
    # Get data
    access={}
    http = Http()
    #des=request.json['eventDescription']
    #print(des)



    try:
        # Convert input unicode string to Python string
        global token
        #token = request.json['accessToken']
        token = 'EwBIA8l6BAAU7p9QDpi/D7xJLwsTgCg3TskyTaQAAbH7enBvh5GJOnHFMc23SS0PzoxVDJ92OHLdu26/m/rirlMptOWVD5MMqylLaU9uyxwEZA6uaEaqi/oEejvpe2o9VY6TLm0dMc1U10jAlWorBfcmNZTDPWGaXnXCvwbeLfiE3wuYZ4fllQuCvPfXLi2xjKqGahZKsQDdvvUVVH56ZUjHodt1H1/ZmlyZ2HuePFLmMUmDooNDVTUCO1DSB1KmOp14OsUiyEw86%2bk57U3ihXPbopEr8evgqCM5%2bpgpeXZeoiBre17E2f2UsaIctjKsKoGmMIDJ%2bONSY8HDhIyEHUbJFDu2/0ouPXRhuv01NgnivYSkJUr0/WwEi8bmsDkDZgAACPFYEjQvLFRnGAL8h0m7P03ZNtDH2AjN5yWkvcC467wgMNkliQ/SNUseE9YdZFBKH/vGc7wQ1Omdr/Db9X4ZG1mw8V3/o5W8T8EyHlLq72EsjxO7skyEU4DxFitCZ5pWVlhfZvQHhxWINPLec3fYwp1vDUg0MVYWpWeRdkfVKbIMU68/GDFxocm9EY0mlD/agPvkoY7y25SHJUs4MeOo0b0dCMmToUegayiZ%2bW%2bOchMQfPoyRLcURjBe2F%2biu8vnm8ybdwyhqM4Xs313W9TB075oSzoKM75p30qhqEh/8iDmDTGgFguPxCZWH5biwGM2K%2bT1AAMoeQ%2bH9lh80UcrIb7zqcFjt/0m35Gyw7S/fj9CcPFl/yiPGL/5kZC5lAbrCZckjkp%2bbyhvSM43WfsWkciz%2bmiDTLqrYBHnY9tKGRLCQbRYZV7gFXo2fGrjq/kUphKuU8OKeFsryq1e3HbbzOz0kwAZ/ZquBXTRrco4gpC2MPuE3xDbuYl5ULvINPik7G3obuiSqrMHnMy7iar/Ec2XHA8zBxkGpnBEV0T16DNW8VK8ShKkrJQcDNrD6mvR26b2mpHRFk33uv%2bJ0R8b3F7%2bk15XIEu6kJAHcL%2bIdm8xo7itMvP15Y7VVi3%2bHjlhPG1fLXAFBh7NJzcDrC6dV3TKDmAZQwqhZYrvoOvq9aV/diKp7PJJQtbkpLlKUdoR2F%2bSGWRptvWKIJauv6Ko6zo/PVYC'
        #print(request.json)
        emails = request.json['attendeeList']
        #emails = ['girishgarg258@outlook.com']
        #print(emails)
        #account = request.json['accountType']
        account = 'Office 365'
        #print(account)
        #user_email = request.json['emailId']
        user_email = 'girishgarg258@outlook.com'
        try:
            #des=request.json['description']
            #des=request.json['subject']   isko uncoment krna hh
            #print(des)
            des = 'testing'
            #des=des+' ' +sub
        except:
            
            #des=request.json['subject']    isko uncoment krna hh
            des = 'testing'
        if account == 'Google':
            #for i, val in enumerate(emails):
            #    globals()["email%d"%i] = val
            access['creds']=token
            #emails=['sumit@eze.ai']
            #des=''
            credentials = AccessTokenCredentials(access['creds'], 'user-agent-value')
            http_auth = credentials.authorize(http)
            gmail_service = discovery.build('gmail', 'v1', http=http)
            querry='('
            if len(emails)==0:
                querry=' -in:chats -in:calendar-notification@google.com after:2017/9/15  '
            for i in range(len(emails)):

                if len(emails)==i+1:
                    querry=querry+emails[-1]+' )' +' -in:chats -in:calendar-notification@google.com after:2017/9/15  '
                #elif len(emails)==0:
                #    querry=querry+' )' +' -in:chats -in:calendar-notification@google.com after:2017/9/15  '
                else:
                    querry=querry+emails[i]+' '+'OR'+' '

            print(querry)
           # querry='( '+info[0]+' OR '+ info[1]+ ' OR ' + info[2]+' )' +' -in:chats after:2017/0/10 '
            #q="( 'vishal@eze.ai' OR 'ikramhussain7786@gmail.com' ) -in:calendar-notification@google.com -in:chats after:2017/08/10"
            findic=get_message(gmail_service,querry,user_id,label_id_one,token)
            print('Message Fetched')
            #print(len(findic))
            rel_mess=[]
            #print(findic)

            new_l=[]
            for i in findic:
                if ('Rem_Send' in i.keys()) and ('Google Calendar' in i['Rem_Send']):
                    print('Done1')

                elif 'Google Calendar' in i['Sender']:
                    print('Done2')
                elif 'config@eze.ai' in i['Sender'] :
                    print('Done3')
                else:
                    new_l.append(i)

            findic = new_l
            #print(findic)


            try:
                for i in findic:
                    email=i['Snippet']


                    email=email+' '+i['Subject']
                    email=email_cleanup(email)
                    pp=i['Subject'].split()
                    h=''
                    for k in pp:
                        h=h+' '+ps.stem(k)
                    email=email+h
                    rel_mess.append(email)
            except KeyError:
                pass

            xx=[]
            print('lenn')
            print(len(findic))
            if des=='':
                for i in range(len(findic)):
                    xx.append(i)
            else:      
                norm_corpus = normalize_corpus(rel_mess, lemmatize=True)
                tfidf_vectorizer, tfidf_features = build_feature_matrix(norm_corpus, feature_type='tfidf',ngram_range=(1, 1), min_df=0.0, max_df=1.0)
                tt=des+ ' ' + ps.stem(des) 
                #print(tt)
                query_docs = [tt]
                norm_query_docs =  normalize_corpus(query_docs, lemmatize=True)            
                query_docs_tfidf = tfidf_vectorizer.transform(norm_query_docs)


            # rel_mess.extend([x['Subject'] for x in findic])

                query_docs_tfidf = tfidf_vectorizer.transform(norm_query_docs)

                for index, doc in enumerate(query_docs):

                    doc_tfidf = query_docs_tfidf[index]
                    top_similar_docs = compute_cosine_similarity(doc_tfidf, tfidf_features)

                for doc_index, sim_score in top_similar_docs:
                    if sim_score>0.20:
                        xx.append(doc_index)
                #print(xx)


            result = []
            for i in xx:

                m_id=findic[i]['threadId']
                thread = gmail_service.users().threads().get(userId="me", id=m_id).execute()
                if len(thread['messages'])>1:
                    th=[]
                    for i in thread['messages']:
                        temp={}
                        header = i['payload']['headers'] 
                        temp['id']=i['id']
                        temp['threadId']=i['threadId']
                        for one in header:

                            if one['name'] == 'Subject':
                                msg_subject = one['value']
                                temp['Subject'] = msg_subject
                            else:
                                pass
                        for two in header: # getting the date
                            if two['name'] == 'Date':
                                msg_date = two['value']
                                date_parse = (parser.parse(msg_date))
                                m_date = (date_parse.date())
                                temp['Date'] = str(m_date)
                            else:
                                pass
                        for three in header: # getting the Sender
                            if three['name'] == 'From':
                                msg_from = three['value']
                                temp['Sender'] = msg_from
                            else:
                                pass
                        for four in header: # getting the Sender
                            if four['name'] == 'To':
                                msg_to = four['value']
                                temp['To'] = msg_to.split(',')
                            else:
                                pass
                        for five in header:
                            if five['name'] == 'Cc':
                                msg_cc = five['value']
                                temp['Cc'] = msg_cc.split(',')
                            else:
                                pass

                            snip=parserr.unescape(i['snippet'])
                            temp['Snippet']=snip

                        temp['labelIds']=i['labelIds'] 

                        if 'Cc' not in temp.keys():
                            temp['Cc'] = []
                        th.append(temp)

                    #h=dict(enumerate(th))
                    result.append(th)
                else:
                    result.append([findic[i]]) 
            #print(xx)
            #print('+======================================')
            #print(result)
            
        if account == 'Office 365':
            #search ="received:04/08/2017..12/26/2017 from:visgupta5"
            print('outlook')
            search = ' '
            
            if len(emails)==0:
                search=' received:04/08/2017..12/26/2017  '
                
            if len(emails)==1:
                search ='received:04/08/2017..12/26/2017 from:'+emails[0]
            if len(emails)>1:
                f_se=''
                for i in emails:
                    f_se=f_se + i + ' OR '
                search ='received:04/08/2017..12/26/2017 from:'+f_se[:-4]
            
            mssg = filter_my_messages(token, user_email,search)
            #print(mssg['value'][0])
            if len(mssg['value'])==0:
                result=[[]]
            if len(mssg['value'])!=0:
                mssg=mssg['value']
                rel_mess = []
                #print(mssg)
                for i in range(len(mssg)):
                    if 'address' in mssg[i]['from']['emailAddress'].keys():
                        mssg[i]['Sender']=mssg[i]['from']['emailAddress']['address']
                    else:
                        mssg[i]['Sender']=mssg[i]['from']['emailAddress']['name']
                    mssg[i]['Date']=mssg[i]['receivedDateTime'][:-1]
                    mssg[i]['Subject']=mssg[i]['subject']

                    mssg[i]['Snippet']=mssg[i]['bodyPreview']

                print(search)    
                try:
                    for i in mssg:

                        email=i['Snippet']
                        email=email+' '+i['subject']
                        email=email_cleanup(email)
                        pp=i['subject'].split()
                        h=''
                        for k in pp:
                            h=h+' '+ps.stem(k)
                        email=email+h
                        rel_mess.append(email)
                except KeyError:
                    pass

                xx=[]
                #print(rel_mess)
                if des=='':
                    for i in range(len(mssg)):
                        xx.append(i)
                else:      
                    norm_corpus = normalize_corpus(rel_mess, lemmatize=True)
                    tfidf_vectorizer, tfidf_features = build_feature_matrix(norm_corpus, feature_type='tfidf',ngram_range=(1, 1), min_df=0.0, max_df=1.0)
                    tt=des+ ' ' + ps.stem(des) 
                    #print(tt)
                    query_docs = [tt]
                    norm_query_docs =  normalize_corpus(query_docs, lemmatize=True)            
                    query_docs_tfidf = tfidf_vectorizer.transform(norm_query_docs)


                # rel_mess.extend([x['Subject'] for x in findic])

                    query_docs_tfidf = tfidf_vectorizer.transform(norm_query_docs)

                    for index, doc in enumerate(query_docs):

                        doc_tfidf = query_docs_tfidf[index]
                        top_similar_docs = compute_cosine_similarity(doc_tfidf, tfidf_features)

                    for doc_index, sim_score in top_similar_docs:
                        if sim_score>0.20:
                            xx.append(doc_index)
                    #print(xx)


                print(search)            
                try:
                    for i in mssg:
                        del i['from']
                        
                        del i['@odata.etag']
                        del i['receivedDateTime']
                        del i['Snippet']
                        del i['subject']
                        i['To']=[]
                        i['threadId']=i['conversationId']
                        i['labelIds']=[]
                        i['Cc']=[]
                except keyError:
                    pass
                resu=[]
                for i in xx:
                    #print(mssg[0])
                    Cid=mssg[int(i)]['threadId']
                    #print(Cid)
                    mss=get_messages_byCid(token, user_email,Cid)
                    mss=mss['value']
                    if len(mss)>1:
                        l=[]
                        for i in range(len(mss)):
                            if 'address' in mss[i]['from']['emailAddress'].keys():
                                mss[i]['Sender']=mss[i]['from']['emailAddress']['address']
                            else:
                                mss[i]['Sender']=mss[i]['from']['emailAddress']['name']
                            mss[i]['Date']=mss[i]['receivedDateTime'][:-1]
                            mss[i]['Subject']=mss[i]['subject']
                            mss[i]['Snippet']=mss[i]['bodyPreview']
                            l.append(mss[i])
                        for i in mss:
                            del i['from']

                            del i['@odata.etag']
                            del i['receivedDateTime']
                            del i['bodyPreview']
                            del i['subject']
                            i['To']=[]
                            #i['threadId']=i['conversationId']
                            i['labelIds']=[]
                            i['Cc']=[]
                        resu.append(l)
                    else:
                        resu.append(mssg[int(i)])
                return jsonify({'task': resu}),201    
                #result=[]
                #result.append(resu)

        #print(result)
        return jsonify({'task': result}),201
    
    except HttpError as err:
        print(err._get_reason())
        return jsonify({'error': err._get_reason()})
    
    except TypeError as error:
        
        print(error._get_reason())
        return jsonify({'error': error._get_reason()})
        
    except Exception as e:
        print(e)
        return jsonify({'error':'error'})


if __name__ == '__main__':

    app.run(host='0.0.0.0',port=8087,debug=True)


    
    
    

#----------- API Call Example -------------- #
#  curl -i -H "Content-Type: application/json" -X POST -d  '{"token": "ya29.Gl3gBA0LFxgDlkulTCv9e4aH3taT4gICuUmj9zj0NGLSrXdRoCxa6to5KQWO5--hKwLpVj9P6lMNqEQzDu-ghcedtYTJ95Yxx5qOF_O7ZGOofLSABH-k6jESORYdFoc","emails":['mohit@eze.ai','sumit@eze.ai'],"description":"site is"}' "http://104.197.124.197:8888/api/post/related"
