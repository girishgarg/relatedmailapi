import json

import flask
import httplib2
import base64

from apiclient import discovery, errors
from oauth2client import client
from html.parser import HTMLParser
from httplib2 import Http
from oauth2client import file, client, tools
from bs4 import BeautifulSoup
import re
import time
import dateutil.parser as parser
from datetime import datetime
import datetime
from flask import Flask, render_template, request, jsonify, make_response


from normalization import normalize_corpus
from utils import build_feature_matrix
import numpy as np
import pandas





#global findic
#findic=[]
#global final_list
#final_list=[]
parserr = HTMLParser()


app = flask.Flask(__name__, static_url_path='/static')

# Path to the client_secret.json file downloaded from the Developer Console
CLIENT_SECRET_FILE = 'client_secre.json'



user_id =  'me'
label_id_one = 'INBOX'
label_id_two = 'UNREAD'


def get_message(service,querry,user_id,label_id_one):
    querry = 'mohit@eze.ai'
    response = service.users().messages().list(userId=user_id,labelIds=[label_id_one],q=querry).execute()
    messages = []

    if 'messages' in response:
        messages.extend(response['messages'])


    while 'nextPageToken' in response:
        page_token = response['nextPageToken']
        response = service.users().messages().list(userId=user_id, q=querry,pageToken=page_token).execute()
        messages.extend(response['messages'])

    final_list = [ ]


    task = [{
    'id': None,
    'Sender': '"email.com" <name@email.com>', 
    'Subject': None, 
    'Date': 'yyyy-mm-dd', 
    'Snippet': None,
    'Message_body': None,
    }]

    for mssg in messages: 
        temp_dict = { }
        m_id = mssg['id'] # get id of individual message
        temp_dict['id'] = m_id
        message = service.users().messages().get(userId=user_id, id=m_id).execute() # fetch the message using API
        payld = message['payload'] # get payload of the message 
        headr = payld['headers'] # get header of the payload


        for one in headr: # getting the Subject
            if one['name'] == 'Subject':
                msg_subject = one['value']
                temp_dict['Subject'] = msg_subject

        for two in headr: # getting the date
            if two['name'] == 'Date':
                msg_date = two['value']
                date_parse = (parser.parse(msg_date))
                m_date = (date_parse.date())
                temp_dict['Date'] = str(m_date)
            else:
                pass

        for three in headr: # getting the Sender
            if three['name'] == 'From':
                msg_from = three['value']
                temp_dict['Sender'] = msg_from
            else:
                pass




        tt=parserr.unescape(message['snippet'])


        temp_dict['Snippet']=tt





        try:
            mssg_parts = payld['parts']
            part_one  = mssg_parts[0]
            part_body = part_one['body']
            part_data = part_body['data']
            clean_one = part_data.replace("-","+")
            clean_one = clean_one.replace("_","/")
            clean_two = base64.b64decode (bytes(clean_one,'utf-8'))
            soup = BeautifulSoup(clean_two , "html" )
            m=soup.get_text()
            mm=parserr.unescape(m)
            #sou = BeautifulSoup(mm , "lxml" )
            #mssg_body = sou.body()
            temp_dict['Message_body'] = mm

        except :
            pass

        final_list.append(temp_dict)

    return final_list


@app.route('/')
def main():
    if 'credentials' in flask.session:
        return flask.redirect(flask.url_for('home'))

    return render_template('main.html')





@app.route('/todo/api/v1.0/tasks', methods=['GET'])
def get_tasks():
    if 'credentials' not in flask.session:
        return make_response(jsonify({'error':'Authentication required'}))
    else:
        return jsonify({'tasks': findic})

@app.route('/todo/api/v1.0/tasks/<int:task_id>', methods=['GET'])
def get_task(task_id):
    if 'credentials' not in flask.session or credentials.access_token_expired:
        return make_response(jsonify({'error':'Authentication required'}))
    else:
        task = [task for task in tasks if task['id'] == task_id]
        if len(task) == 0:
            abort(404)
        return jsonify({'task': task[0]})


@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)



@app.route('/todo/api/v1.0/tasks', methods=['POST'])
def create_task():
    if 'credentials' not in flask.session or credentials.access_token_expired:
        return make_response(jsonify({'error':'Authentication required'}))
    else:
        if not request.json or not 'title' in request.json:
            abort(400)
        http = httplib2.Http()
        http_auth = credentials.authorize(http)
        # Build the Gmail service from discovery
        gmail_service = discovery.build('gmail', 'v1', http=http)
        querry = request.form.get('text')
        findic=get_message(gmail_service,querry,user_id,label_id_one)
        data=jsonify({'task': findic})
        return data, 201


@app.route('/home',methods=['GET','POST'])
def home():
    if 'credentials' not in flask.session:
        return flask.redirect(flask.url_for('oauth2callback'))
    credentials = client.OAuth2Credentials.from_json(flask.session['credentials'])
    if credentials.access_token_expired:
        return flask.redirect(flask.url_for('oauth2callback'))
    else:
        return  render_template('home.html')
    
    return render_template('home.html')


@app.route('/index',methods=['GET','POST'])
def index():
    if 'credentials' not in flask.session:
        return flask.redirect(flask.url_for('oauth2callback'))
    credentials = client.OAuth2Credentials.from_json(flask.session['credentials'])
    if credentials.access_token_expired:
        return flask.redirect(flask.url_for('oauth2callback'))
    else:
        http = httplib2.Http()
        http_auth = credentials.authorize(http)
        # Build the Gmail service from discovery
        gmail_service = discovery.build('gmail', 'v1', http=http)
        querry = 'mohit@eze.ai'
        
        findic=get_message(gmail_service,querry,user_id,label_id_one)
        data=jsonify({'task': findic})
           
        #if request.method=='POST':
        #    return  render_template('related.html')

        return render_template('index.html', findic=findic)
       


@app.route('/oauth2callback')
def oauth2callback():
    flow = client.flow_from_clientsecrets(
          CLIENT_SECRET_FILE,
          scope=['https://www.googleapis.com/auth/gmail.modify'],
          redirect_uri=flask.url_for('oauth2callback', _external=True))
    if 'code' not in flask.request.args:
        auth_uri = flow.step1_get_authorize_url()
        return flask.redirect(auth_uri)
    else:
        auth_code = flask.request.args.get('code')
        credentials = flow.step2_exchange(auth_code)
        flask.session['credentials'] = credentials.to_json()
        return flask.redirect(flask.url_for('home'))

def compute_cosine_similarity(doc_features, corpus_features,top_n=3):
    # get document vectors
    doc_features = doc_features[0]
    # compute similarities
    similarity = np.dot(doc_features,corpus_features.T)
    similarity = similarity.toarray()[0]
    # get docs with highest similarity scores
    top_docs = similarity.argsort()[::-1][:top_n]
    top_docs_with_score = [(index, round(similarity[index], 3))  for index in top_docs]

    return top_docs_with_score

def email_cleanup(email):
    """
    Cleaning up raw text of emails
    """
    email = email.replace('\n', " ").lower()
    email = email.replace('\n', " ")

    patterns = [
    # # Remove From: LastName, FirstName, Optional Middle Initial
    r"from: (\w+), (\w+) (\w+)?",
    # Dates
    r"(date):? \d+/\d+/\d+",
    # # Remove Case Numbers. Example: Case No. F-2015-04841
    r"case no. \w-\d+-\d+",
    # # Remove times. Example: 12:08 PM
    r"[0-2]?[0-9]:[0-6][0-9] (am|pm)",
    # Removing Timestamps in Sent
    r"(sent|updated)?:? (monday|tuesday|wednesday|thursday|friday|saturday|sunday), (january|february|march|april|may|june|july|august|september|october|november|december) \d+, \d{4} \d{0,2}:\d{0,2} (am|pm)",
    # Remove emails
    r"[\w]+@[\.\w]+",
    # Dates 2
    r"(monday|tuesday|wednesday|thursday|friday|saturday|sunday)",
    # Removing months
    r"january|february|march|april|may|june|july|august|september|october|november|december",
    # Removing doc numbers
    r"doc no. \w?\d+",
    # Removing email footer STATE DEPT. - PRODUCED TO HOUSE SELECT BENGHAZI COMM.
    r"state dept. - produced to house select benghazi comm.",
    # Removing email footer SUBJECT TO AGREEMENT ON SENSITIVE INFORMATION & REDACTIONS.
    r"subject to agreement on sensitive information & redactions.",
    # Removing email footer
    r"no foia waiver.",
    # Removing leftover characters
    r"[\@!<>()&-:';]",
    # remove all digits
    #r"\d"
    ]
    
    for pattern in patterns:
        email = re.sub(pattern, " ", email)
    email = re.sub('\s+', ' ', email)
    email = email.encode('ascii', 'ignore')
    email = email.decode()
    return email


@app.route('/related', methods=['GET','POST'])
def related():

    credentials = client.OAuth2Credentials.from_json(flask.session['credentials'])
    http = httplib2.Http()
    http_auth = credentials.authorize(http)
    # Build the Gmail service from discovery
    gmail_service = discovery.build('gmail', 'v1', http=http)
    querry = 'mohit@eze.ai'
        
    findic=get_message(gmail_service,querry,user_id,label_id_one)
    print(findic)
  
    rel=[]
    for i in findic:
        temp={}
        for key, value in i.items():
            if key=='id':
                temp['id']=value
            if key=='Message_body':
                temp['Message_body']=value
            if key=='Subject':
                temp['Subject']=value
            rel.append(temp)
    rel_mess=[]
    try:
        for i in findic:
            email=i['Message_body']
            email=email_cleanup(email)
            rel_mess.append(email)
    except KeyError:
        pass
    print (rel_mess)
    print (len(rel_mess))
    #rel_mess = [x['Message_body'] for x in rel]


    norm_corpus = normalize_corpus(rel_mess, lemmatize=True)
    tfidf_vectorizer, tfidf_features = build_feature_matrix(norm_corpus, feature_type='tfidf',ngram_range=(1, 1), min_df=0.0, max_df=1.0)

    query_docs = ['Regarding']
    norm_query_docs =  normalize_corpus(query_docs, lemmatize=True)            
    query_docs_tfidf = tfidf_vectorizer.transform(norm_query_docs)


    # rel_mess.extend([x['Subject'] for x in findic])

    query_docs_tfidf = tfidf_vectorizer.transform(norm_query_docs)

    for index, doc in enumerate(query_docs):
    
        doc_tfidf = query_docs_tfidf[index]
        top_similar_docs = compute_cosine_similarity(doc_tfidf, tfidf_features, top_n=4)
    xx = []
    s=[]
    print ('Document',index+1 ,':', doc)
    print ('Top', len(top_similar_docs), 'similar docs:')
    for doc_index, sim_score in top_similar_docs:

        try:
            xx.append(rel_mess[doc_index+1])
        except:
            pass
        s.append(sim_score)
        
        
        print ('Doc num: {} Similarity Score: {}\nDoc: {}'.format(doc_index+1, sim_score, rel_mess[doc_index])  )
    print(xx)
    print(s)
    return render_template('related.html',xx=xx, s=s  )




if __name__ == '__main__':
  import uuid
  app.secret_key = str(uuid.uuid4())
  app.debug = True
  app.run()
