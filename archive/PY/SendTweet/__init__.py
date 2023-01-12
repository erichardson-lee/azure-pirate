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

def main(mytimer: func.TimerRequest) -> None:

    try:
        # variables for accessing SBQ
        queue_name = "totweet"
        connstr = os.environ['ServiceBusConnectionStrListenOnly']
    except Exception as e:
        logging.critical(f"Could not pull connstr var from env with error: {str(e)}")
    
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
        logging.info(f"img url: {url}")
        logging.info(f"message: {str(message)}")
        try:
            filename = '/tmp/tmpimg.jpg'
            request = requests.get(url, stream=True)
            if request.status_code == 200:
                with open(filename, 'wb') as image:
                    for chunk in request:
                        image.write(chunk)

                twitter.update_status_with_media(filename=filename, status=str(message))
                os.remove(filename)
                logging.info(f">>>>>>>>>>>>>>>>>>>>>>>>>>>>>> tweet sent (with media): {str(message)}")
            else:
                twitter.update_status(str(message))
                logging.warning(f"Unable to download image. Sent tweet without it. status_code = {request.status_code} url = {url}")
                logging.info(f">>>>>>>>>>>>>>>>>>>>>>>>>>>>>> tweet sent (without media): {str(message)}")
        except Exception as e:
            logging.critical(f"Could not run tweet_image func with error: {str(e)}")

    try:
        servicebus_client = ServiceBusClient.from_connection_string(conn_str=connstr, logging_enable=True)
    except Exception as e:
        logging.critical(f"Could not create servicebus_client with error: {str(e)}")
    
    try:
        with servicebus_client:
            # get the Queue Receiver object for the queue
            receiver = servicebus_client.get_queue_receiver(queue_name=queue_name, max_wait_time=10)
            with receiver:
                for msg in receiver:
                    if msg:
                        try:
                            
                            try:
                                regularex = r"(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|(([^\s()<>]+|(([^\s()<>]+)))))+(?:(([^\s()<>]+|(([^\s()<>]+))))|[^\s`!()[]{};:'\".,<>?«»“”‘’]))"
                                urlsrc = re.findall(regularex,str(msg))
                                url =  [url[0] for url in urlsrc][0]
                            except Exception as e:
                                logging.critical(f"Could not extract URL from msg with error: {str(e)}. urlsrc = {urlsrc}. url = {url}.")
                                break

                            if 'youtube' in url:
                                logging.info(url)
                                try:
                                    vID = url.split("v=")[1]
                                except Exception as e:
                                    logging.critical(f"Could not get vID with error: {str(e)}")
                                imgUrl = f"https://img.youtube.com/vi/{vID}/sddefault.jpg"
                                try:
                                    tweet_image(imgUrl, str(msg))
                                    # logging.info(f"Sent tweet (with media). Message: {str(msg)}. Image: {imgUrl}.")
                                    receiver.complete_message(msg)
                                    break
                                except Exception as e:
                                    receiver.dead_letter_message(
                                        msg,
                                        reason="ProcessingError",
                                        error_description=f"{str(e)}",
                                    )
                                    logging.critical(f"Could not send Tweet (with media) with error: {str(e)}")
                            else:
                                try:
                                    twitter.update_status(str(msg))
                                    logging.info(f">>>>>>>>>>>>>>>>>>>>>>>>>>>>>> tweet sent (without media): {str(msg)}")
                                    # logging.info(f"Sent tweet (without media). Message: {str(msg)}.")
                                    receiver.complete_message(msg)
                                    break
                                except Exception as e:
                                    receiver.dead_letter_message(
                                        msg,
                                        reason="ProcessingError",
                                        error_description=f"{str(e)}",
                                    )
                                    logging.critical(f"Could not send Tweet (without media) with error: {str(e)}")

                        except Exception as e:
                            receiver.dead_letter_message(
                                msg,
                                reason="ProcessingError",
                                error_description=f"{str(e)}",
                            )
                            logging.critical(f"Could not send Tweet with error: {str(e)}")

    
    except Exception as e:
        logging.critical(f"Could not process queue error: {str(e)}")