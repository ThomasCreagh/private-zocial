# Private Zocial
A crypto key management system that wraps mastadon written in zig
![architecture diagram](architecture.png)

## How to run:
First create an application on the target mastadon instance.
You can find the docs to create an application on https://docs.joinmastodon.org/client/token/#app.
> Note! Private zocial only works with mastadon instances with longer character limits such as 2000chars. (I just self hosted my own to get around this and set the limit to a million which did the job).

The main command to get your application id and secret is:
```bash
curl -X POST \
	-F 'client_name=Test Application' \
	-F 'redirect_uris=urn:ietf:wg:oauth:2.0:oob' \
	-F 'scopes=read write push' \
	-F 'website=https://myapp.example' \
	https://mastodon.example/api/v1/apps
```
Next create a `config.zig` file in the `src/` folder in the same format as `config.example.zig` and fill out the missing parameters after you run the curl command to get your app id and secret.
Then run the following:
```bash
git clone https://github.com/ThomasCreagh/private-zocial
zig build -Doptimize=ReleaseFast
./zig-out/bin/private_zocail
```

## About the Project
### In scope:
- wrap a social media site
- allow users to key exchange
- be able to message indiviuals with encryption
- be able to create groups and message with encrytion
- give messages ids to allow clients not to have to attempt to decrypt all messages

### Not in scope:
- security on client device
- public keys with valid certs etc
- was planning to have admins to control members who can join but everyone can leak the key so I think just give the key to all and trust them all. If people decide to remove someone just invite others to a new group.

### Links:
- aes-128 https://mojoauth.com/encryption-decryption/aes-128-encryption--zig/#introduction-to-aes-128
- ecc-192 https://compile7.org/encryption-decryption/how-to-use-ecc-192-to-encrypt-and-decrypt-in-zig/#generating-ecc-192-key-pairs
