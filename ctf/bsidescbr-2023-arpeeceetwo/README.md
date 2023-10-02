# Arpeeceetwo BSidesCbr 2023 CTF write-up

Unofficial write-up, will link to official one when it's out.

## Background

The challenge name "Arpeeceetwo" gives a hint that this is RPC related. Also
two something? Hold that thought.

The description was:

```
We've identified a small exhaust port in the AI's core matrix. It might be
large enough to fire two photon torpedos down, but we'll need to bypass the
access gate first. It seems to be behind this application...

python client.py -r arpeeceetwo.chal.cybears.io:2323

(You will need to compile the .proto file using googles protobuf)
```

The supplied materials are a server ([server.py](server.py)) and client ([client.py](client.py)), with a
Google Protocol Buffer (proto) schema ([server.proto](server.proto)) that they use to talk to
each other.

The client is already fully functioning (after compiling the proto) and can
create a user and attempt to call the "flag" endpoint. Only admins are allowed
to call that endpoint so it denies us when run.

## Development setup

_If you're familiar with protobuf just run `protoc` and skip most of this part._

You'll need the protobuf libraries installed, as well as pycrpyto and pwntool
as the client uses them.

I use NixOS, so I ran a shell with the dependencies installed:

```console
$ nix-shell -p python310Packages.pwntools python310Packages.protobuf python310Packages.pycrypto
```

pip or other packaging systems work too, although you may need to install the
protoc compiler first (e.g. protobuf-compiler on Ubuntu):

```console
$ python3 -m venv ctf-rpc2
$ source ctf-rpc2/bin/activate
$ pip install pycrypto protobuf pwntools
```

The proto file provided is the schema source code, with protocol buffers you
need to compile it for each language you wish to use it with. The proto file
uses "proto2" syntax, it needs to be compiled with protoc:

```console
$ protoc -I=. --python_out=. ./server.proto
```

(This is from the comment at the top of server.py.)

To run the server you'll need to supply a fake flag file:

```console
$ echo "flag='you{got-it}'" > cybears.py
```

After this you can recreate the challenge against a local server:

```console
# Command from the top of server.py
$ socat -d TCP-LISTEN:2323,reuseaddr,fork EXEC:"python3 server.py" &
$ python3 client.py -r localhost:2323
[...]
[*] DEBUG: received type: MSG_FLAG_RESPONSE
    uid: 2
    status: FAILURE
    msg: "Welcome uid:2. you are not an admin, no flag for you"
[*] Closed connection to localhost port 2323
```

(When I tried this on Ubuntu I got an
[error](https://developers.google.com/protocol-buffers/docs/news/2022-05-06#python-updates),
per the error we don't care about speed, so to workaround the mismatched
versions from Ubuntu and pip, do `export
PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION=python` like the error suggests.)

## RPC flow

The first thing to understand are the RPCs the client and server communicate
via. If you're not familiar with protobuf you may find it helpful to [read
a](https://protobuf.dev/getting-started/pythontutorial/) little [about
it](https://protobuf.dev/programming-guides/encoding/).

The client makes it pretty clear what the RPCs it makes are, see the main body where there are comments like `## REGISTER`, etc.

### Create a user

Register supplies a username and password, and gets a response which has the
UID and a status (success/failure).

Because this is a CTF challenge each connection is actually a unique instance
of the server, there's no backing database, so you know that your first created
user will always have UID 2.

The password is simply hashed with MD5, using the password concatenated with
the salt.

The admin user is created with a 32 byte random password on startup and will
always have the ID of 1. (Hint: The RNG here is good and attacking that is not
what we're looking for.)

### Login and call an endpoint

Once we've logged in the other endpoints just need a valid token, which login
supplies us with.

The token is made up from:

```python
def build_token(uid, role, salt):
    t = spb.UnsignedToken()
    t.uid = uid
    t.role = role
    t.salt = salt
    return t
```

Where that protocol buffer is serialized to binary (proto calls this
`SerializeToString` because the API presumably predates Python 3, it is binary)
and then signed:

```python
m = MD5.new(token.SerializeToString()).digest()
st.signature = hmac.new(KEY, m).digest()
```

Where KEY is a randomly generated 32 bytes at startup.

Attempts to make a `MSG_FLAG_REQUEST` are denied because our role in the token
isn't admin.

## The flaw

<details>
<summary>There's some hints above, or expand for the full spoilers...

</summary>

One strange detail you may have noticed is we can supply the user's salt. The
salt is used both to salt their password and as part of the session token.
In addition all that is in `UnsignedToken` is the UID, the role and the salt.
There's no nonce or anything that stops the token being different on each
login; this is a bad idea, but this alone isn't going to get us anything other
than the ability to do a replay attack, we want to elevate privileges.

This `UnsignedToken` is signed by MD5ing the binary serialised proto and then
applying HMAC to it. We do not know `KEY`, so cannot attack the HMAC (I did
wonder for a moment if the solution was some kind of extension attack on the
HMAC, but that doesn't make sense).

We can however hash collide the MD5 generated before the HMAC is applied.
Generating the collisions requires some knowledge of the protocol buffer format
and MD5 collision tooling.

Protobufs have a [format](https://protobuf.dev/programming-guides/encoding/)
where each field has an ID, which are represented on the wire by that ID
(encoded as a varint), followed by the field's value, which for variable length
fields like a string is the field's length (varint again), followed by the raw
data. This means in the proto message after the salt's length, the rest of the
data in the message is totally under our control.

This means we can hash collide the MD5 by using
[hashclash's](https://github.com/cr-marcstevens/hashclash) chosen-prefix
collision (cpc) tool. We generate one input where `role` is set to `1`
(`ADMIN`) and one where the role is set to `0`, which will match the token we
can predict the application will give us.

When we login and provide the salt from the collided user token the other admin
token we generated will have same MD5 as the one the app already signed for us,
so we can use the signature we were given, but our admin token. Logging in with
that will mean the server will believe we have the admin role.

### Generating the collisions

The hashclash tooling by default generates 512 byte long collisions, at least
for short inputs. We generate two inputs, from serialising the desired protos:

```python
import server_pb2 as spb

out = "a"

for role in spb.USER, spb.ADMIN:
    t = spb.UnsignedToken()
    t.uid = 2  # Known UID
    t.role = role
    t.salt = b' ' * 505  # Makes serialized data 512 bytes long
    with open(out + str(role), "wb") as f:
      f.write(t.SerializeToString())
```

(I've cleaned that script up for clarity, in reality I just hex edited the
`\x00` to `\x01` for the second version.)

Then we generate collisions (run this in tmux):
```
mkdir cpc_collide
cd cpc_collide
../script/cpc.sh a0 a1
```

This will _eventually_ give us a0.coll and a1.coll.

We can then modify client.py to use these:

```diff
--- client.py.old	2023-10-02 06:28:18.876257658 +0000
+++ client.py	2023-10-02 06:30:47.092560397 +0000
@@ -88,11 +88,16 @@

     s = remote(host,port )

+    with open("a0.coll", "rb") as a0r:
+      a0 = spb.UnsignedToken()
+      a0.ParseFromString(a0r.read(512))
+
     ## REGISTER
     rr = spb.RegisterRequest()
     rr.type = spb.MSG_REGISTER_REQUEST
     rr.name = b"TestName"
     rr.password = b"TestPassword"
+    rr.salt = a0.salt
     send_message(s, rr)

     ## REGISTER RESPONSE
@@ -125,12 +130,17 @@
     if msg_resp != None:
         log.info("DEBUG: received {}".format(msg_resp))

+    with open("a1.coll", "rb") as a1r:
+      a1 = spb.UnsignedToken()
+      a1.ParseFromString(a1r.read(512))
+
     ## REQUEST FLAG AS USER
     flag_req = spb.FlagRequest()
     flag_req.type = spb.MSG_FLAG_REQUEST
     flag_req.uid = login_resp.uid
     flag_req.role = spb.USER
-    flag_req.token.CopyFrom(login_resp.token)
+    flag_req.token.signature = login_resp.token.signature
+    flag_req.token.token.CopyFrom(a1)

     send_message(s, flag_req)
```

```shell
$ python3 client.py -r arpeeceetwo.chal.cybears.io:2323
[+] Opening connection to arpeeceetwo.chal.cybears.io on port 2323: Done
[*] DEBUG: received type: MSG_REGISTER_RESPONSE
    uid: 2
    status: SUCCESS
[*] DEBUG: received type: MSG_LOGIN_RESPONSE
    uid: 2
    status: SUCCESS
    token {
      token {
        uid: 2
        role: USER
        salt: "\327\315\206\345_\320\203\001\233MU\006a\253\210\021\212\372M4\263uYFV\227\357lJ\007\220\314\376\031\327\317o\222\003\234\221\252\245\332V\000\000\000\000\331`\365\311\353\226Z\261a\361C\364\013:(\312\255\303!\252[.\365\321\026\356\320\226\314\006 l\033g\336\216\345S\014\261\022\205\242\216P<e\240$\264J\363;\311\243L\274\312\353 \3476\321 \211)\004c]\312\245D\336\210\334nv}\204G.\273\246O\331\312\223\216\r\305\217u\323\346\333kl\210\225/f\314\211\322\261[\277\202\014\204\005\246\375\255\241\027\034J\361\212\274K\334p\267p\212F\310\324\367X[\271\251\306\365\211\217\345\'\330\025AR\226\"\260Ij\235\007e\275\362\377\323\277=\221\023\275\314\234<\237\030\371Xor7\357\307\246\345\023\017\213[\245\\3\206\375\373\254\211\311Qc\255\237\306\'\\\241\340b\245\355\207\304\277\2650\241+\360>k\017\232\263L\227tQ\206\273\311\020\353\'\001U\337\325\0163\346\357\340\027W\340\246\354\253\270\202\006PYs;\234\314\313\210\2750\225x 1\020\210\034P\327\301\3663\232\257\232\306e!Ww\252\3614+\215\310\204\322\277R\345W(&\302A\367h\363\256\223\304\325X\n\036\215\321z\004\027\324\253\252\364\263,\357\213\362(v\274\037^Uf\266B\260p-U@\023\024\356\3144\0329P\003\323\320\3352\230/\343luf\003Q\t\321\224\266\265\373\244y\325C\205\376G\373\017t\007\241m\342[\320@\243U\232\337\213\352\235\240\342B{s\2263\270\313\010\2317\265\214\202\377\246\211\001\310\323\230\335\3254\217hy\004\0058\334\277\277\374\376\305\340i\000_\251\346t\276\232^{ \331\344\337\365\332\201[\003\310^\307}\265\265\250\266\207\031\221\202\263u\260\310Q\314\374\336m\320"
      }
      signature: "6\256\002\361\347\312y\355\017\234~\263L\001\2750"
    }
[*] DEBUG: received type: MSG_MESSAGE_RESPONSE
    uid: 2
    status: SUCCESS
    msg: "Welcome uid:2, your role is 0"
[*] DEBUG: received type: MSG_FLAG_RESPONSE
    uid: 2
    status: SUCCESS
    msg: "Welcome uid:2, here is your FLAG: cybears{R2D2s_f4v3_mus1c_15_b33pb0x1ng!}"
[*] Closed connection to arpeeceetwo.chal.cybears.io port 2323
```

I've provided a0.coll and a1.coll if you want to try it out without generating them.

## Summary

Generating the collisions took around 4 hours on a i7-12700T (maybe a GPU would
make that significantly faster, but I didn't have the hardware available). I
got the inputs wrong the first time, so in total it took 8 hours, one run while
I was sleeping.

I liked this challenge as it really brought home the point that MD5 is broken.

Real world takeaways:

- Say no to MD5
- Use good randomness in a session token. See for example [CAPEC-196](https://capec.mitre.org/data/definitions/196.html).
  (While JWT have their own problems, probably better than inventing your own broken session tokens.)
- Don't use salt for any purpose other than hashing passwords. Ideally don't let user supply them.
- Do something better than `md5(password || salt)` but the poor password hashing didn't help us here.

</details>
