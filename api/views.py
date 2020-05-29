import base64
import hashlib
import json

from Crypto.Cipher import DES
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from django.http import HttpResponse, Http404
from django.views.decorators.csrf import csrf_exempt


def get_md5(request):
    if request.method != 'GET':
        raise Http404

    text = request.GET.get("text", "")

    result = hashlib.md5(text.encode('utf-8')).hexdigest()
    response = {
        "result": result
    }
    return HttpResponse(json.dumps(response),
                        status=200,
                        content_type='application/json; charset=utf-8')


def get_sha1(request):
    if request.method != 'GET':
        raise Http404

    text = request.GET.get("text", "")

    result = hashlib.sha1(text.encode('utf-8')).hexdigest()
    response = {
        "result": result
    }
    return HttpResponse(json.dumps(response),
                        status=200,
                        content_type='application/json; charset=utf-8')


def get_sha224(request):
    if request.method != 'GET':
        raise Http404

    text = request.GET.get("text", "")

    result = hashlib.sha224(text.encode('utf-8')).hexdigest()
    response = {
        "result": result
    }
    return HttpResponse(json.dumps(response),
                        status=200,
                        content_type='application/json; charset=utf-8')


def get_sha256(request):
    if request.method != 'GET':
        raise Http404

    text = request.GET.get("text", "")

    result = hashlib.sha256(text.encode('utf-8')).hexdigest()
    response = {
        "result": result
    }
    return HttpResponse(json.dumps(response),
                        status=200,
                        content_type='application/json; charset=utf-8')


def get_sha384(request):
    if request.method != 'GET':
        raise Http404

    text = request.GET.get("text", "")

    result = hashlib.sha384(text.encode('utf-8')).hexdigest()
    response = {
        "result": result
    }
    return HttpResponse(json.dumps(response),
                        status=200,
                        content_type='application/json; charset=utf-8')


def get_sha512(request):
    if request.method != 'GET':
        raise Http404

    text = request.GET.get("text", "")

    result = hashlib.sha512(text.encode('utf-8')).hexdigest()
    response = {
        "result": result
    }
    return HttpResponse(json.dumps(response),
                        status=200,
                        content_type='application/json; charset=utf-8')


@csrf_exempt
def des_encode(request):
    def pad(text):
        while len(text) % 8 != 0:
            text += b' '
        return text

    if request.method != 'POST':
        raise Http404

    text = request.POST.get("text", "")
    key = request.POST.get("key", "")

    key = key.encode('utf-8')
    padded_text = pad(text.encode('utf-8'))

    des = DES.new(key, DES.MODE_ECB)
    result = des.encrypt(padded_text)
    response = {
        "result": base64.b64encode(result).decode('utf-8')
    }
    return HttpResponse(json.dumps(response),
                        status=200,
                        content_type='application/json; charset=utf-8')


@csrf_exempt
def des_decode(request):
    if request.method != 'POST':
        raise Http404

    text = request.POST.get("text", "")
    key = request.POST.get("key", "")

    key = key.encode('utf-8')
    text = base64.b64decode(text.encode('utf-8'))

    des = DES.new(key, DES.MODE_ECB)
    result = des.decrypt(text)
    response = {
        "result": result.decode('utf-8')
    }
    return HttpResponse(json.dumps(response),
                        status=200,
                        content_type='application/json; charset=utf-8')


def rsa_generate_key(request):
    if request.method != 'GET':
        raise Http404

    code = 'nooneknows'
    key = RSA.generate(2048)

    encrypted_key = key.exportKey(
        passphrase=code,
        pkcs=8,
        protection="scryptAndAES128-CBC"
    )

    private_key = encrypted_key
    public_key = key.publickey().exportKey()

    private_key = base64.b64encode(private_key)
    public_key = base64.b64encode(public_key)

    response = {
        "private_key": private_key.decode('utf-8'),
        "public_key": public_key.decode('utf-8'),
    }
    return HttpResponse(json.dumps(response),
                        status=200,
                        content_type='application/json; charset=utf-8')


@csrf_exempt
def rsa_encode(request):
    if request.method != 'POST':
        raise Http404

    text = request.POST.get("text", "")
    public_key = request.POST.get("public_key", "")

    text = text.encode('utf-8')
    public_key = base64.b64decode(public_key.encode('utf-8'))

    recipient_key = RSA.import_key(public_key)

    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(text)

    result = cipher_rsa.encrypt(session_key) + cipher_aes.nonce + tag + ciphertext
    result = base64.b64encode(result)

    response = {
        "result": result.decode('utf-8')
    }
    return HttpResponse(json.dumps(response),
                        status=200,
                        content_type='application/json; charset=utf-8')


@csrf_exempt
def rsa_decode(request):
    if request.method != 'POST':
        raise Http404

    text = request.POST.get("text", "")
    private_key = request.POST.get("private_key", "")

    code = 'nooneknows'
    text = text.encode('utf-8')
    text = base64.b64decode(text)
    private_key = base64.b64decode(private_key.encode('utf-8'))

    private_key = RSA.import_key(
        private_key,
        passphrase=code
    )

    size_in_bytes = private_key.size_in_bytes()
    enc_session_key = text[:size_in_bytes]
    nonce = text[size_in_bytes:size_in_bytes + 16]
    tag = text[size_in_bytes + 16:size_in_bytes + 32]
    ciphertext = text[size_in_bytes + 32:]

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    result = cipher_aes.decrypt_and_verify(ciphertext, tag)

    response = {
        "result": result.decode('utf-8')
    }
    return HttpResponse(json.dumps(response),
                        status=200,
                        content_type='application/json; charset=utf-8')
