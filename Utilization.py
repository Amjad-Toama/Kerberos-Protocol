def nonce_update(nonce):
    new_nonce = get_value(nonce) - 1
    return new_nonce.to_bytes(8, byteorder='big')


def get_value(nonce):
    return int.from_bytes(nonce, byteorder='big')
