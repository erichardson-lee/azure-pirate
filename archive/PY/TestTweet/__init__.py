import datetime
import logging
import os
import azure.functions as func
from azure.servicebus import ServiceBusClient, ServiceBusMessage
import sys
import requests
import base64
import tweepy
import json
from pathlib import Path
import re

logging.basicConfig(level=logging.INFO)

##

def main(req: func.HttpRequest) -> func.HttpResponse:

    try:
        # variables for accessing twitter API
        consumer_key = os.environ['TwitterApiKey']
        consumer_secret_key = os.environ['TwitterApiSecret']
        access_token = os.environ['TwitterAccessToken']
        access_token_secret = os.environ['TwitterAccessTokenSecret']
    except Exception as e:
        logging.critical(f"Could not pull Twitter vars from env with error: {str(e)}")

    try:
        auth = tweepy.OAuthHandler(consumer_key, consumer_secret_key)
        auth.set_access_token(access_token, access_token_secret)
        twitter = tweepy.API(auth)
    except Exception as e:
        logging.critical(f"Could not pull create twitter client with error: {str(e)}")

    def tweet_image(url, message):
        logging.warning(f"img url: {url}")
        logging.warning(f"message: {str(message)}")
        try:
            filename = '/tmp/tmpimg.jpg'
            request = requests.get(url, stream=True)
            if request.status_code == 200:
                with open(filename, 'wb') as image:
                    for chunk in request:
                        image.write(chunk)

                twitter.update_status_with_media(filename=filename, status=str(message))
                os.remove(filename)
            else:
                logging.critical(f"Unable to download image. status_code = {request.status_code} url = {url}")
                twitter.update_status(str(message))
        except Exception as e:
            logging.critical(f"Could not run tweet_image func with error: {str(e)}")

    ##### message only test
    # try:
    #     twitter.update_status("Yarr!!")
    # except Exception as e:
    #     logging.critical(f"Could not run send tweet with error: {str(e)}")

    ##### YouTube test
    # https://www.youtube.com/watch?v=9pZ2xmsSDdo
    msg = "Avast Ye!\n\nNew YouTube post from @Njuchi_ called: DevOps Roadmap 2022 - How to become a DevOps Engineer? What is DevOps?\n\nCheck it out it here: https://www.youtube.com/watch?v=9pZ2xmsSDdo\n\n#Azure #AzureFamily #CloudFamily #AzurePirate"

    try:
                            
        try:
            regularex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|(([^\s()<>]+|(([^\s()<>]+)))))+(?:(([^\s()<>]+|(([^\s()<>]+))))|[^\s`!()[]{};:'\".,<>?«»“”‘’]))"
            urlsrc = re.findall(regularex,str(msg))
            url =  [url[0] for url in urlsrc][0]
        except Exception as e:
            logging.critical(f"Could not extract URL from msg with error: {str(e)}")

        if 'youtube' in url:
            logging.warning(f"vid url: {url}")
            try:
                vID = url.split("v=")[1]
            except Exception as e:
                logging.critical(f"Could not get vID with error: {str(e)}")
            imgUrl = f"https://img.youtube.com/vi/{vID}/sddefault.jpg"
            try:
                tweet_image(imgUrl, str(msg))
                logging.warning(f"Sent tweet (with media). Message: {str(msg)}. Image: {imgUrl}.")
            except Exception as e:
                logging.critical(f"Could not send Tweet (with media) with error: {str(e)}")

    except Exception as e:
        logging.critical(f"Could not send Tweet with error: {str(e)}")

    return func.HttpResponse(
            "This HTTP triggered function executed successfully. Pass a name in the query string or in the request body for a personalized response.",
            status_code=200
    )
