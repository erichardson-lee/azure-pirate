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
import re
from pathlib import Path
from tweepy import Cursor
import time

import warnings
warnings.filterwarnings("error")

logging.basicConfig(level=logging.INFO)

def main(mytimer: func.TimerRequest) -> None:

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
        api = tweepy.API(auth, wait_on_rate_limit=False)
    except Exception as e:
        logging.critical(f"Could not pull create twitter client with error: {str(e)}")

    people_I_follow = api.get_friend_ids(screen_name='Azure Pirate')
    logging.info(f"people_I_follow: {len(people_I_follow)}")

    people_that_follow_me = api.get_follower_ids(screen_name='Azure Pirate')
    logging.info(f"people_that_follow_me: {len(people_that_follow_me)}")

    try:
        for follower in tweepy.Cursor(api.get_followers).items():
            if follower not in tweepy.Cursor(api.get_friends).items():
                try:
                    follower.follow()
                    logging.info(f"Followed: {follower.screen_name}")
                except Exception as e:
                    logging.warning(f"Tried to follow: {follower.screen_name}. Handled error: {e}. Skipping...")
                    continue
    except Exception as e:
        logging.warning(f"Error captured: {e}")
