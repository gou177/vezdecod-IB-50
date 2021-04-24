import click
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP


@click.group()
def app():
    """Консольная утилита для шифрования и дешифрования сообщений"""


@app.command("encode")
@click.option("--file-from", default="./msg.bin", help="Файл, из которого делать шифр")
@click.option("--from-cli/--no-cli", default=True, help="Запрашивать сообщение из консоли")
@click.option(
    "--file-out", default="./msg.bin", help="Путь для зашифрованного сообщения"
)
@click.option(
    "--public-key-path", default="./public.pem", help="Путь до публичного ключа"
)
def encode(file_out, file_from, from_cli, public_key_path):
    """Шифрует сообщение с помощью публичного ключа"""
    if from_cli:
        data = input("Сообщение: ")
        data = data.encode("utf-8")
    else:
        with open(file_from, "rb") as f:
            data = f.read()

    with open(public_key_path) as f:
        public_key = RSA.import_key(f.read())

    session_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(public_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    with open(file_out, "wb") as f:
        [f.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]


@app.command("decode")
@click.option(
    "--file-in", default="./msg.bin", help="Путь до зашифрованного сообщения"
)
@click.option(
    "--file-out", default="./msg.txt", help="Путь до разшифрованного сообщения"
)
@click.option(
    "--private-key-path", default="./private.pem", help="Путь до приватного ключа"
)
@click.option(
    "--write-to-file/--no-write-to-file",
    default=False,
    help="Если true, то пишем в файла, вместо консоли",
)
def decode(file_in, file_out, write_to_file, private_key_path):
    """Дешифрует сообщение с помощью приватного ключа"""
    private_key = RSA.import_key(open(private_key_path).read())

    with open(file_in, "rb") as f:
        enc_session_key, nonce, tag, ciphertext = [
            f.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)
        ]

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    if write_to_file:
        with open(file_out, "wb") as f:
            f.write(data)
        return

    print(data.decode("utf-8"))


@app.command("generate")
@click.option(
    "--file-private", default="./private.pem", help="Путь для выходного приватного ключа"
)
@click.option(
    "--file-public", default="./public.pem", help="Путь для выходного публичного ключа"
)
def generate(file_private, file_public):
    """Генерирует приватный и публичный ключи"""
    key = RSA.generate(2048)
    private_key = key.export_key()

    with open(file_private, "wb") as f:
        f.write(private_key)

    public_key = key.publickey().export_key()
    with open(file_public, "wb") as f:
        f.write(public_key)


if __name__ == "__main__":
    app()
