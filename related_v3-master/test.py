.import json

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
from oauth2client.client import AccessTokenCredentials
import time

from normalization import normalize_corpus
from utils import build_feature_matrix
import numpy as np
import pandas
import requests

from nltk.stem import PorterStemmer

parserr = HTMLParser()
ps = PorterStemmer()

app = flask.Flask(__name__, static_url_path='/static')

# Path to the client_secret.json file downloaded from the Developer Console
#CLIENT_SECRET_FILE = 'ccc.json'



user_id =  'me'
label_id_one = 'INBOX'
label_id_two = 'UNREAD'


def get_message(service,querry,user_id):
    response = service.users().messages().list(userId=user_id,q=querry).execute()
    messages = []
    print(messages)

    if 'messages' in response:
        messages.extend(response['messages'])


    while 'nextPageToken' in response:
        page_token = response['nextPageToken']
        response = service.users().messages().list(userId=user_id, q=querry,pageToken=page_token).execute()
        messages.extend(response['messages'])

    final_list = [ ]

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


@app.route('/asd')
def main():
    if 'credentials' in flask.session:
        return flask.redirect(flask.url_for('index'))

    return render_template('main.html')

'''
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

'''
@app.route('/index')
def index():
    '''
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
    '''
    return render_template('index.html')
      

def test():
    e1 = request.form['e1']
    e2 = request.form['e2']
    e3 = request.form['e3']
    des = request.form['des']
    info = [e1,e2,e3,des]
    us = request.form['us']
    return info


@app.route('/index',methods=['POST'])
def index_view():
    '''
    if 'credentials' not in flask.session:
        return flask.redirect(flask.url_for('oauth2callback'))
    credentials = client.OAuth2Credentials.from_json(flask.session['credentials'])
    if credentials.access_token_expired:
        return flask.redirect(flask.url_for('oauth2callback'))
    else:
    '''
    aaa={}
    
    
    if request.method == 'POST':    
        e1 = request.form['e1']
        e2 = request.form['e2']
        e3 = request.form['e3']
        des = request.form['des']
        us = request.form['us']
        #info = [e1,e2,e3,des]
        #print(info)
        http = Http()
        url = "http://www.eze.ai/google/accesstoken?emailId="+us
        r=requests.get(url)
        aaa['creds']=r.text
        credentials = AccessTokenCredentials(aaa['creds'], 'user-agent-value')
        http_auth = credentials.authorize(http)
    # Build the Gmail service from discovery
        gmail_service = discovery.build('gmail', 'v1', http=http)
        info = test()
        print (info)
       # querry= "from:"+info[0]+ "from:"+info[1] + "from:" + info[2] 
        querry='('+info[0]+' OR '+ info[1]+ ' OR ' + info[2]+')' +' -in:chats after:2017/07/10'
        print(querry)
        start_time = time.time()
        findic=get_message(gmail_service,querry,user_id) 
 
        rel_mess=[]
        try:
            for i in findic:
                email=i['Snippet']
                email=email+' '+ i['Subject']
                
                email=email_cleanup(email)
                pp=i['Subject'].split()
                h=''
                for k in pp:
                    h=h+' '+ps.stem(k)
                email=email + h
                rel_mess.append(email)
        except KeyError:
            pass
        #print (len(rel_mess))
        xx = []
        new=[]
        print(des=='')
    #rel_mess = [x['Message_body'] for x in rel]
        if info[3]=='':
            for i in range(len(findic)):
                xx.append(i)

        else:      
            norm_corpus = normalize_corpus(rel_mess, lemmatize=True)
            tfidf_vectorizer, tfidf_features = build_feature_matrix(norm_corpus, feature_type='tfidf',ngram_range=(1, 1), min_df=0.0, max_df=1.0)
            tt=des+ ' ' + ps.stem(info[3]) 
            print(tt)
            query_docs = [tt]
            norm_query_docs =  normalize_corpus(query_docs, lemmatize=True)            
            query_docs_tfidf = tfidf_vectorizer.transform(norm_query_docs)


        # rel_mess.extend([x['Subject'] for x in findic])

            query_docs_tfidf = tfidf_vectorizer.transform(norm_query_docs)

            for index, doc in enumerate(query_docs):
        
                doc_tfidf = query_docs_tfidf[index]
                top_similar_docs = compute_cosine_similarity(doc_tfidf, tfidf_features)
            
            for doc_index, sim_score in top_similar_docs:
                if sim_score>0.0:
                    xx.append(doc_index)
            print(xx)
           
        tim=time.time() - start_time
        for i in xx:
            print(rel_mess[i])
            new.append(findic[i])
        return render_template('submit.html',  findic = findic,new=new,tim=tim)

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
        return flask.redirect(flask.url_for('index'))

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




if __name__ == '__main__':
  import uuid
  app.secret_key = str(uuid.uuid4())
  app.debug = True
  app.run(host='0.0.0.0',port=8000,debug=True)
