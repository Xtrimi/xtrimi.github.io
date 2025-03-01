from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad
from Crypto.Util.number import *
from alive_progress import alive_bar

def unlocker(flag):
    def key_decryptor(ciphertext):
        c = bytes_to_long(ciphertext)
        (d, n) = (0x2477CEFD961FE9B45BF3FC942F011DF849F40A5D56CE69E93ADEC92F18C71F91E52CED416AE9B5AF5311290DAB85D852CA7D11C56853063B4371119AA1A585B79FC11720A3F750302BBDE4CD46433E22F7C5FD03B69E0B846834A0BFF50E7CBF46C59F24562F886130E591AACEEFF89A50AF45728FCAC6CD3690EF5F984190366E67C9F1725ED9EE014E3CA3C45106C6B5C4EDDD8DBE760F2428F3856BDEE99B909CC332C75719FC3ED22BC398E2AA65AF87BD31B0455D443D0285CC14C284FFE61967B1FA0657BB5957C2629FEC7F215C0BD37908436ED98B1B389D342C612F1E0DC9F67900365EBA07D462A2C3BB83F0296824CA4A5651D5E29FA5913F370D, 0x745486641242C2CF6333B47DE52D28072D1F97597179693FBEB519D43D08B6D51BA293AF81F06E8FE0B49410C108029985DC6429BE637DBDF49D835DE7B43B86810640F0C645284D9A52D1A632C5343FD241D3700D6127E43C1280D2CDB3E39CB588FA07EA9DC1A1CA3AEB883CD775DDF2FC734E941F22342D2EF6730E21D2D2D782DCD55EE186122EC7D0976354A995CB4CBD7922C197075E446959C259CAB2BE6AB7FA8AAF0CD972BFA212138DA1D7AF087B6C8F14811983F09762FA6D5E8A0B9240EE71CC9919F3407ED504F32BF028D3EB9B51B4A74B776D8759401016C204E5F49C19958C71C3E012A5523E644BE725D6C9DE420CDAA10820FD8FFE9845)
        m = pow(c, d, n)
        plaintext = long_to_bytes(m)
        return b'\x00' * (48 - len(plaintext)) + plaintext

    print('Starting decryption...')
    with alive_bar(256, title='Decrypting') as bar:
        for i in range(256):
            now_key = key_decryptor(flag[-256:])
            flag = flag[:-256]
            cipher = AES.new(key=now_key[:32], mode=AES.MODE_CBC, iv=now_key[32:])
            flag = cipher.decrypt(flag)
            flag = unpad(flag, 16)
            bar()
    f = open('flag.png', 'wb')
    f.write(flag)
    f.close()

#serial_number = input('Enter the serial number to unlock this product: ')
#if serial_number == 'WA4Au-l10ub-18T7W-u9Yx2-Ms4Rl':
#    print('Unlocking...')
unlocker(open('flag.png.locked', 'rb').read())
#None('Invalid serial number. Access denied.')