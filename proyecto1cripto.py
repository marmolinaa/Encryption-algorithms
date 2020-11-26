# -*- coding: utf-8 -*-
"""
PROYECTO 1 CRIPTOGRAFÍA

Librería utiizada: Cryptodome
Documetación: https://pycryptodome.readthedocs.io/en/latest/src/api.html
"""
#AES ECB y AES CBC
from Cryptodome.Cipher import AES
#SHA-2 384
from Cryptodome.Hash import SHA384
#SHA-2 512
from Cryptodome.Hash import SHA512
#SHA-3 384
from Cryptodome.Hash import SHA3_384
#SHA-3 512
from Cryptodome.Hash import SHA3_512
#RSA OAEP y PSS
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.Signature import pkcs1_15
from Cryptodome.Signature import pss
#DSA Y ECDSA
from Cryptodome.PublicKey import DSA
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from Cryptodome.Hash import SHA256
#Para estadística de los resultados y tiempos
import pandas as pd
from time import time
import statistics

'''///////////////////////////////////////////////// A E S ////////////////////////////////////////////////////'''

#---------------------------AES ECB-----------------------------------------
listEBC_C =[]  #Lista de tiempos cifrados
listEBC_D =[]  #Lista de tiempos descifrados
listK=[]  #Lista llaves
listM=[]  #Lista mensajes

archivo = open("EBC_AES.rsp","r")
for linea in archivo.readlines():
    if "KEY = " in linea: #Lee las llaves del archivo
        fKey = linea.lstrip("KEY = ")
        listK.append(fKey.rstrip("\n"))
    elif "PLAINTEXT = " in linea:#Lee los mensajes del archivo
        M = linea.lstrip("PLAINTEX = ")
        listM.append(M.rstrip("\n"))
        
#print("\n *****************AES EBC********************* ")
for i in range(0, 50):
    for i in range(0, len(listM)):
        #CIFRADO
        mensaje = bytearray.fromhex(listM[i]) 
        key = bytearray.fromhex(listK[i])
        cifrar = AES.new(key, AES.MODE_ECB)
        timeI = time()
        ct_bytes = cifrar.encrypt(mensaje)
        timeF=time()
        listEBC_C.append(timeF-timeI)
        #print(ct_bytes.hex())
        #DESCIFRADO
        timeI = time()
        descifrar= cifrar.decrypt(ct_bytes)
        timeF = time()
        listEBC_D.append(timeF-timeI)
        #print(descifrar.hex())
archivo.close()
#---------------------------AES CBC-----------------------------------------
listCBC_C =[]  #Lista de tiempos cifrados
listCBC_D =[]  #Lista de tiempos descifrados
listK=[]  #Lista llaves
listM=[]  #Lista mensaje
listIV=[] #Lista vectores de inicialización

archivo = open("CBC_AES.rsp","r")
for linea in archivo.readlines():
    if "KEY = " in linea:#Lee las llaves del archivo
        fKey = linea.lstrip("KEY = ")
        listK.append(fKey.rstrip("\n"))
    elif "PLAINTEXT = " in linea:#Lee los mensajes del archivo
        M = linea.lstrip("PLAINTEX = ")
        listM.append(M.rstrip("\n"))
    elif "IV = " in linea:#Lee los vecotres de inicialización del archivo
        initvec = linea.lstrip("IV = ")
        listIV.append(initvec.rstrip("\n"))

#print("\n *****************AES CBC********************* ")
for i in range(0, 50):
    for i in range(0, len(listM)):
        #CIFRADO
        mensaje = bytearray.fromhex(listM[i]) 
        key = bytearray.fromhex(listK[i])
        iv = bytearray.fromhex(listIV[i])
        cifrar = AES.new(key, AES.MODE_CBC, iv)
        timeI = time()
        ct = cifrar.encrypt(mensaje)
        timeF=time()
        listCBC_C.append(timeF-timeI)
        #print(ct.hex())
        #DESCIFRADO
        descifrar = AES.new(key, AES.MODE_CBC, iv)
        timeI=time()
        desc = descifrar.decrypt(ct)
        timeF=time()
        listCBC_D.append(timeF-timeI)
        #print(desc.hex())
archivo.close()

#---------------------------------RESULTADOS AES--------------------------
columnsAES = ['EBC_C', 'EBC_D','CBC_C', 'CBC_D']
tmp_promAES = [statistics.mean(listEBC_C), statistics.mean(listEBC_D),statistics.mean(listCBC_C), statistics.mean(listCBC_D)]

print('EBC_C: ', tmp_promAES[0],
        '\nEBC_D: ', tmp_promAES[1],
        '\nCBC_C: ',tmp_promAES[2],
        '\nCBC_D: ', tmp_promAES[3])
print("\n\n")

#ESCRITURA DE RESULTADOS DE AES EN EXCEL
dataAES = {'EBC_C': listEBC_C,
        'EBC_D': listEBC_D,
        'CBC_C': listCBC_C,
        'CBC_D': listCBC_D}

dfaes = pd.DataFrame(dataAES, columns = columnsAES)
dfaes.to_excel('EjecucionAES.xlsx', sheet_name='AES')



'''////////////////////////////////////////////////////////////////////////////////////////////////////////////'''

'''///////////////////////////////////////////////// S H A ////////////////////////////////////////////////////'''
#Función para leer los datos de los archivos SHA
def leeArchivoSHA(doc):
    listaMsg = []
    archivo = open(doc,"r")
    for linea in archivo.readlines():
        if "Msg = " in linea:#Lee los mensajes del archivo
            if len(listaMsg)<50:
                  mensaje = linea.lstrip("Msg = ")
                  listaMsg.append(mensaje.rstrip("\n"))
            else: break
    archivo.close()
    return listaMsg

#--------------------------- SHA-2 384 -----------------------------------------
#HASH
#print("\n *****************SHA2-384********************* ")
datos = leeArchivoSHA("SHA384ShortMsg.rsp") + leeArchivoSHA("SHA384LongMsg.rsp")
listaTmpoSHA384 = [] #Lista de tiempos SHA-2 384
h = SHA384.new()
for i in range(0, 50):
    for dato in datos:
        timeI = time()
        h.update(bytearray.fromhex(dato))
        timeF=time()
        listaTmpoSHA384.append(timeF-timeI)
        #print(h.hexdigest())

#--------------------------- SHA-2 512 -----------------------------------------
#HASH
#print("\n *****************SHA2-512********************* ")
datos = leeArchivoSHA("SHA512ShortMsg.rsp") + leeArchivoSHA("SHA512LongMsg.rsp")
listaTmpoSHA512 = [] #Lista de tiempos SHA-2 512
h = SHA512.new()
for i in range(0, 50):
    for dato in datos:
        timeI = time()
        h.update(bytearray.fromhex(dato))
        timeF=time()
        listaTmpoSHA512.append(timeF-timeI)
        #print(h.hexdigest())

#--------------------------- SHA-3 384  -----------------------------------------
#HASH
#print("\n *****************SHA3-384********************* ")
datos = leeArchivoSHA("SHA3_384ShortMsg.rsp") + leeArchivoSHA("SHA3_384LongMsg.rsp")
listaTmpoSHA3_384 = []
h = SHA3_384.new()
for i in range(0, 50):
    for dato in datos:
        timeI = time()
        h.update(bytearray.fromhex(dato))
        timeF=time()
        listaTmpoSHA3_384.append(timeF-timeI)
        #print(h.hexdigest())
    
#--------------------------- SHA-3 512  -----------------------------------------
#HASH
#print("\n *****************SHA3-512********************* ")
datos = leeArchivoSHA("SHA3_512ShortMsg.rsp") + leeArchivoSHA("SHA3_512LongMsg.rsp")
listaTmpoSHA3_512 = []
h = SHA3_512.new()
for i in range(0, 50):
    for dato in datos:
        timeI = time()
        h.update(bytearray.fromhex(dato))
        timeF=time()
        listaTmpoSHA3_512.append(timeF-timeI)
        #print(h.hexdigest())

#---------------------------------RESULTADOS SHA--------------------------
columnsSHA = ['SHA384','SHA512','SHA3_384','SHA3_512']
tmp_promSHA=[statistics.mean(listaTmpoSHA384),statistics.mean(listaTmpoSHA512),statistics.mean(listaTmpoSHA3_384), statistics.mean(listaTmpoSHA3_512)]
print('SHA384: ', tmp_promSHA[0],
        '\nSHA512: ', tmp_promSHA[1],
        '\nSHA3_384: ', tmp_promSHA[2],
        '\nSHA3_512: ', tmp_promSHA[3])
print("\n\n")

#ESCRITURA DE RESULTADOS DE SHA EN EXCEL
dataSHA = {'SHA384': listaTmpoSHA384,
        'SHA512': listaTmpoSHA512,
        'SHA3_384': listaTmpoSHA3_384,
        'SHA3_512': listaTmpoSHA3_512}
df = pd.DataFrame(dataSHA, columns = columnsSHA)
df.to_excel('EjecucionSHA.xlsx', sheet_name='SHA') 

'''////////////////////////////////////////////////////////////////////////////////////////////////////////////'''

'''///////////////////////////////////////////////// R S A////////////////////////////////////////////////////'''
   
#--------------------------- RSA OAEP  -----------------------------------------
#FIRMAS
#print("\n *****************RSA OAEP********************* ")
#GENERAR FIRMA
listn=[]#Lista del parametro n
listMsg=[]#Lista de los mensajes
liste=[]#Lista del parametro e
listd=[]#Lista del parametro d
timeGenRSA_OAEP=[]#Lista de tiempos de generacion de firmas
timeVerRSA_OAEP=[]#Lista de tiempos de verificación de firmas
encrypTime = []#Lista de tiempos de cifrado de texto
decrypTime = []#Lista de tiempos de decifrado de texto

archivo=open("SigGenRSA_OAEP.txt","r")
for linea in archivo.readlines():
    if "n = " in linea:#Lee el parametro n del archivo
        fn = linea.lstrip("n = ")
        listn.append(fn.rstrip("\n"))
    elif "Msg = " in linea:#Lee los mensajes del archivo
        m = linea.lstrip("Msg = ")
        listMsg.append(m.rstrip("\n"))
    elif "e = " in linea:#Lee el parametro e del archivo
        fe = linea.lstrip("e = ")
        liste.append(fe.rstrip("\n"))
    elif "d = " in linea:#Lee el parametro Y del archivo
        fd = linea.lstrip("d = ")
        listd.append(fd.rstrip("\n"))
archivo.close()

n = int(listn[0],16)
e = int(liste[0],16)
d = int(listd[0],16)

privateKEY=RSA.construct((n,e,d))
publicKEY=RSA.construct((n,e))
listMsgAux = listMsg

for i in range(0, 6):
    for i in range(0, len(listMsg)): 
        Msg = bytearray.fromhex(listMsg[i])

        timeI=time()
        h=SHA256.new(Msg)
        firma=pkcs1_15.new(privateKEY).sign(h)
        timeF=time()
        timeGenRSA_OAEP.append(timeF-timeI)
        #print(firma.hex(),'\n')

#VERIFICAR FIRMA
listn=[]#Lista del parametro n
listMsg=[]#Lista de los mensajes
liste=[]#Lista del parametro e
listS=[]#Lista la firma S

archivo=open("SigVerRSA_PSS.txt","r")
for linea in archivo.readlines():
    if "n = " in linea:#Lee el parametro n del archivo
        fn = linea.lstrip("n = ")
        listn.append(fn.rstrip("\n"))
    elif "Msg = " in linea:#Lee los mensajes del archivo
        m = linea.lstrip("Msg = ")
        listMsg.append(m.rstrip("\n"))
    elif "e = " in linea:#Lee el parametro e del archivo
        fe = linea.lstrip("e = ")
        liste.append(fe.rstrip("\n"))
    elif "S = " in linea:#Lee la firma s del archivo
        fs = linea.lstrip("S = ")
        listS.append(fs.rstrip("\n"))
archivo.close()

n = int(listn[0],16)
for i in range(0, 10):
    for i in range(0, len(listMsg)): 
        e = int(liste[i],16)
        Msg = bytearray.fromhex(listMsg[i])
        S = bytearray.fromhex(listS[i])

        key=RSA.construct((n,e))
        timeI=time()
        h=SHA256.new(Msg)
        try:
            pkcs1_15.new(key).verify(h,S)
            ver=True
            #print("Verificar firma:")
            #print("Firma valida")
        except(ValueError, TypeError):
            #print("Firma no valida")
            ver=False
        timeF=time()
        timeVerRSA_OAEP.append(timeF-timeI)

for aux in range(len(listMsgAux)):
    timeI=time()
    cipher = PKCS1_OAEP.new(publicKEY)
    ciphertext = cipher.encrypt(bytearray.fromhex(listMsgAux[i]))
    timeF=time()
    encrypTime.append(timeF-timeI)

    timeI=time()
    cipher = PKCS1_OAEP.new(privateKEY)
    message = cipher.decrypt(ciphertext)
    timeF=time()
    decrypTime.append(timeF-timeI)

#--------------------------- RSA PSS  -----------------------------------------
#FIRMAS
#print("\n *****************RSA PSS********************* ")
#GENERAR FIRMA
listn=[]#Lista del parametro n
listMsg=[]#Lista de los mensajes
liste=[]#Lista del parametro e
listd=[]#Lista del parametro d
timeGenRSA_PSS=[]#Lista de tiempos de generacion de firmas
timeVerRSA_PSS=[]#Lista de tiempos de verificación de firmas

archivo=open("SigGenRSA_PSS.txt","r")
for linea in archivo.readlines():
    if "n = " in linea:#Lee el parametro n del archivo
        fn = linea.lstrip("n = ")
        listn.append(fn.rstrip("\n"))
    elif "Msg = " in linea:#Lee los mensajes del archivo
        m = linea.lstrip("Msg = ")
        listMsg.append(m.rstrip("\n"))
    elif "e = " in linea:#Lee el parametro e del archivo
        fe = linea.lstrip("e = ")
        liste.append(fe.rstrip("\n"))
    elif "d = " in linea:#Lee el parametro Y del archivo
        fd = linea.lstrip("d = ")
        listd.append(fd.rstrip("\n"))
archivo.close()

n = int(listn[0],16)
e = int(liste[0],16)
d = int(listd[0],16)
for i in range(0, 6):
    for i in range(0, len(listMsg)): 
        Msg = bytearray.fromhex(listMsg[i])
        
        key=RSA.construct((n,e,d))
        timeI=time()
        h=SHA256.new(Msg)
        #firma = pss.new(key,salt_bytes=SaltVal).sign(h)
        firma = pss.new(key).sign(h)
        timeF=time()
        timeGenRSA_PSS.append(timeF-timeI)
        #print(firma.hex(),'\n')

#VERIFICAR FIRMA
listn=[]#Lista del parametro n
listp=[]#Lista del parametro p
listq=[]#Lista del parametro q
listMsg=[]#Lista de los mensajes
liste=[]#Lista del parametro e
listd=[]#Lista del parametro d
listS=[]#Lista la firma S

archivo=open("SigVerRSA_PSS.txt","r")
for linea in archivo.readlines():
    if "n = " in linea:#Lee el parametro n del archivo
        fn = linea.lstrip("n = ")
        listn.append(fn.rstrip("\n"))
    elif "p = " in linea:#Lee el parametro p del archivo
        fp = linea.lstrip("p = ")
        listp.append(fp.rstrip("\n"))
    elif "q = " in linea:#Lee el parametro q del archivo
        fq = linea.lstrip("q = ")
        listq.append(fq.rstrip("\n"))
    elif "Msg = " in linea:#Lee los mensajes del archivo
        m = linea.lstrip("Msg = ")
        listMsg.append(m.rstrip("\n"))
    elif "e = " in linea:#Lee el parametro e del archivo
        fe = linea.lstrip("e = ")
        liste.append(fe.rstrip("\n"))
    elif "d = " in linea:#Lee el parametro Y del archivo
        fd = linea.lstrip("d = ")
        listd.append(fd.rstrip("\n"))
    elif "S = " in linea:#Lee la firma s del archivo
        fs = linea.lstrip("S = ")
        listS.append(fs.rstrip("\n"))
archivo.close()

n = int(listn[0],16)
p = int(listp[0],16)
q = int(listq[0],16)
for i in range(0, 10):
    for i in range(0, len(listMsg)):  
        e = int(liste[i],16)
        d = int(listd[i],16)
        Msg = bytearray.fromhex(listMsg[i])
        S = bytearray.fromhex(listS[i])

        key=RSA.construct((n,e,d,p,q),False)
        timeI=time()
        h=SHA256.new(Msg)
        try:
            pss.new(key).verify(h,S)
            ver=True
            #print("Verificar firma:")
            #print("Firma valida")
        except(ValueError, TypeError):
            #print("Firma no valida")
            ver=False
        timeF=time()
        timeVerRSA_PSS.append(timeF-timeI)

#---------------------------------RESULTADOS RSA--------------------------
columnsRSA = ['RSAOAEP_Gen','RSAOAEP_Ver','RSAPSS_Gen','RSAPSS_Ver']
tmp_promRSA=[statistics.mean(timeGenRSA_OAEP), statistics.mean(timeVerRSA_OAEP), statistics.mean(timeGenRSA_PSS), statistics.mean(timeVerRSA_PSS), statistics.mean(encrypTime), statistics.mean(decrypTime)]
print('RSAOAEP_Gen: ', tmp_promRSA[0],
      '\nRSAOAEP_Ver: ', tmp_promRSA[1],
      '\nRSAPSS_Gen: ', tmp_promRSA[2],
      '\nRSAPSS_Ver: ', tmp_promRSA[3],
      '\nRSAOAEP_Enc: ', tmp_promRSA[4],
      '\nRSAOAEP_Dec: ', tmp_promRSA[5])
print("\n\n")

#ESCRITURA DE RESULTADOS DE SHA EN EXCEL
dataRSA = {'RSAOAEP_Gen': timeGenRSA_OAEP,
        'RSAOAEP_Ver': timeVerRSA_OAEP,
             'RSAPSS_Gen': timeGenRSA_PSS,
        'RSAPSS_Ver': timeVerRSA_PSS}

df = pd.DataFrame(dataRSA, columns = columnsRSA)
df.to_excel('EjecucionRSA.xlsx', sheet_name='RSA')

'''////////////////////////////////////////////////////////////////////////////////////////////////////////////'''

'''///////////////////////////////////////////////// D S A////////////////////////////////////////////////////'''

#--------------------------- DSA  -----------------------------------------
#FIRMAS
#print("\n *****************DSA********************* ")
#GENERAR FIRMA
listP=[]#Lista del parametro P
listQ=[]#Lista del parametro Q
listG=[]#Lista del parametro G
listMsg=[]#Lista de los mensajes
listX=[]#Lista del parametro X
listY=[]#Lista del parametro Y
timeGenDSA=[]#Lista de tiempos de generacion de firmas
timeVerDSA=[]#Lista de tiempos de verificación de firmas

archivo=open("SigGenDSA.txt","r")
for linea in archivo.readlines():
    if "P = " in linea:#Lee el parametro P del archivo
        fp = linea.lstrip("P = ")
        listP.append(fp.rstrip("\n"))
    elif "Q = " in linea:#Lee el parametro Q del archivo
        fQ = linea.lstrip("Q = ")
        listQ.append(fQ.rstrip("\n"))
    elif "G = " in linea:#Lee el parametro G del archivo
        fG = linea.lstrip("G = ")
        listG.append(fG.rstrip("\n"))
    elif "Msg = " in linea:#Lee los mensajes del archivo
        m = linea.lstrip("Msg = ")
        listMsg.append(m.rstrip("\n"))
    elif "X = " in linea:#Lee el parametro X del archivo
        fx = linea.lstrip("X = ")
        listX.append(fx.rstrip("\n"))
    elif "Y = " in linea:#Lee el parametro Y del archivo
        fy = linea.lstrip("Y = ")
        listY.append(fy.rstrip("\n"))
archivo.close()

P = int(listP[0],16)
Q = int(listQ[0],16)
G = int(listG[0],16)
for i in range(0, 4):
    for i in range(0, len(listMsg)):   
        Msg = bytearray.fromhex(listMsg[i])
        X = int(listX[i],16)
        Y = int(listY[i],16)
        #K =int("85976c5610a74959531040a5512b347eac587e48",16)
        
        key=DSA.construct((Y,G,P,Q,X))
        timeI=time()
        firma=DSS.new(key, "fips-186-3")
        h=SHA256.new(Msg)
        sign_fir=firma.sign(h)
        timeF=time()
        timeGenDSA.append(timeF-timeI)
        #print("Generar firma:")
        #print(sign_fir.hex())

#VERIFICAR FIRMA
listP=[]#Lista del parametro P
listQ=[]#Lista del parametro Q
listG=[]#Lista del parametro G
listMsg=[]#Lista de los mensajes
listX=[]#Lista del parametro X
listY=[]#Lista del parametro Y
listR=[]#Lista de firmas R
listS=[]#Lista de firmas S

archivo=open("SigVerDSA.rsp","r")
for linea in archivo.readlines():
    if "P = " in linea:#Lee el parametro P del archivo
        fp = linea.lstrip("P = ")
        listP.append(fp.rstrip("\n"))
    elif "Q = " in linea:#Lee el parametro Q del archivo
        fQ = linea.lstrip("Q = ")
        listQ.append(fQ.rstrip("\n"))
    elif "G = " in linea:#Lee el parametro G del archivo
        fG = linea.lstrip("G = ")
        listG.append(fG.rstrip("\n"))
    elif "Msg = " in linea:#Lee los mensajes del archivo
        m = linea.lstrip("Msg = ")
        listMsg.append(m.rstrip("\n"))
    elif "X = " in linea:#Lee el parametro X del archivo
        fx = linea.lstrip("X = ")
        listX.append(fx.rstrip("\n"))
    elif "Y = " in linea:#Lee el parametro Y del archivo
        fy = linea.lstrip("Y = ")
        listY.append(fy.rstrip("\n"))
    elif "R = " in linea:#Lee la firma R del archivo
        fr = linea.lstrip("R = ")
        listR.append(fr.rstrip("\n"))
    elif "S = " in linea:#Lee la firma s del archivo
        fs = linea.lstrip("S = ")
        listS.append(fs.rstrip("\n"))
archivo.close()

P = int(listP[0],16)
Q = int(listQ[0],16)
G = int(listG[0],16)
for i in range(0, 4):
    for i in range(0, len(listMsg)):
        Msg = bytearray.fromhex(listMsg[i])
        X = int(listX[i],16)
        Y = int(listY[i],16)
        R = bytearray.fromhex(listR[i])
        S = bytearray.fromhex(listS[i])

        key=DSA.construct((Y,G,P,Q,X), False)
        timeI=time()
        verifica=DSS.new(key,"fips-186-3")
        h=SHA256.new(Msg)
        try:
            verifica.verify(h,R+S)
            ver=True
            #print("Verificar firma:")
            #print("Firma valida")
        except(ValueError, TypeError):
            #print("Firma no valida")
            ver=False
        timeF=time()
        timeVerDSA.append(timeF-timeI)

#---------------------------------RESULTADOS DSA--------------------------
columnsDSA = ['DSAGEN','DSAVER']
tmp_promDSA=[statistics.mean(timeGenDSA), statistics.mean(timeVerDSA)]
print('DSAGEN: ', tmp_promDSA[0],
        '\nDSAVER: ', tmp_promDSA[1])
print("\n\n")

#ESCRITURA DE RESULTADOS DE SHA EN EXCEL
dataDSA = {'DSAGEN': timeGenDSA,
        'DSAVER': timeVerDSA}

df = pd.DataFrame(dataDSA, columns = columnsDSA)
df.to_excel('EjecucionDSA.xlsx', sheet_name='DSA')

'''////////////////////////////////////////////////////////////////////////////////////////////////////////////'''

'''///////////////////////////////////////////////// E C D S A////////////////////////////////////////////////////'''
    
#--------------------------- ECDSA  -----------------------------------------
#FIRMAS
#print("\n *****************ECC********************* ")
#ECDSA PRIME FIELD P-521
#GENERAR FIRMA
listd=[]#Lista del parametro d
listQX=[]#Lista del punto X
listQY=[]#Lista del punto Y
listMsg=[]#Lista de los mensajes
listR=[]#Lista de firmas R
listS=[]#Lista de firmas S
timeGenECC_521=[]#Lista de tiempos de generacion de firmas
timeVerECC_521=[]#Lista de tiempos de verificación de firmas

archivo=open("ECC_P521_GEN.txt","r")
for linea in archivo.readlines():
    if "Qx = " in linea:#Lee el punto X del archivo
        fQx = linea.lstrip("Qx = ")
        listQX.append(fQx.rstrip("\n"))
    elif "Qy = " in linea:#Lee el punto Y del archivo
        fQy = linea.lstrip("Qy = ")
        listQY.append(fQy.rstrip("\n"))
    elif "Msg = " in linea:#Lee los mensajes del archivo
        m = linea.lstrip("Msg = ")
        listMsg.append(m.rstrip("\n"))
    elif "R = " in linea:#Lee la firma R del archivo
        fr = linea.lstrip("R = ")
        listR.append(fr.rstrip("\n"))
    elif "S = " in linea:#Lee la firma s del archivo
        fs = linea.lstrip("S = ")
        listS.append(fs.rstrip("\n"))
    elif "d = " in linea:#Lee el parametro Y del archivo
        fd = linea.lstrip("d = ")
        listd.append(fd.rstrip("\n"))
archivo.close()

for i in range(0, 4):
    for i in range(0, len(listMsg)):
        Msg = bytearray.fromhex(listMsg[i])
        Qx = int(listQX[i],16)
        Qy = int(listQY[i],16)
        d = int(listd[i],16)
        
        key=ECC.construct(curve="P-521",d=d,point_x= Qx,point_y= Qy)#llave privada
        timeI=time()
        h=SHA3_512.new(Msg)#Ocupamos este hash porque ECDSA pide más seguridad
        firma=DSS.new(key,"fips-186-3")
        sign_fir=firma.sign(h)
        timeF=time()
        timeGenECC_521.append(timeF-timeI)
        #print(sign_fir.hex(),"\n")

#VERIFICAR FIRMA
listQX=[]#Lista del punto X
listQY=[]#Lista del punto Y
listMsg=[]#Lista de los mensajes
listR=[]#Lista de firmas R
listS=[]#Lista de firmas S

archivo=open("ECC_P521_VER.txt","r")
for linea in archivo.readlines():
    if "Qx = " in linea:#Lee el punto X del archivo
        fQx = linea.lstrip("Qx = ")
        listQX.append(fQx.rstrip("\n"))
    elif "Qy = " in linea:#Lee el punto Y del archivo
        fQy = linea.lstrip("Qy = ")
        listQY.append(fQy.rstrip("\n"))
    elif "Msg = " in linea:#Lee los mensajes del archivo
        m = linea.lstrip("Msg = ")
        listMsg.append(m.rstrip("\n"))
    elif "R = " in linea:#Lee la firma R del archivo
        fr = linea.lstrip("R = ")
        listR.append(fr.rstrip("\n"))
    elif "S = " in linea:#Lee la firma s del archivo
        fs = linea.lstrip("S = ")
        listS.append(fs.rstrip("\n"))
archivo.close()

for i in range(0, 4):
    for i in range(0, len(listMsg)):
        Msg = bytearray.fromhex(listMsg[i])
        Qx = int(listQX[i],16)
        Qy = int(listQY[i],16)
        R = bytearray.fromhex("0"+listR[i])
        S = bytearray.fromhex("0"+listS[i])

        key=ECC.construct(curve="P-521",point_x= Qx,point_y= Qy)#llave pública
        timeI=time()
        verifica=DSS.new(key,"fips-186-3")
        h=SHA256.new(Msg)
        try:
            verifica.verify(h,R+S)
            #print("Verificar firma:")
            #print("Firma valida")
            ver=True
        except(ValueError, TypeError):
            #print("Firma no valida")
            ver=False
        timeF=time()
        timeVerECC_521.append(timeF-timeI)  

#---------------------------------------ECDSA PRIME FIELD P-384-----------------------------------
#GENERAR FIRMA
listd=[]#Lista del parametro d
listQX=[]#Lista del punto X
listQY=[]#Lista del punto Y
listMsg=[]#Lista de los mensajes
listR=[]#Lista de firmas R
listS=[]#Lista de firmas S
timeGenECC_384=[]#Lista de tiempos de generacion de firmas
timeVerECC_384=[]#Lista de tiempos de verificación de firmas

archivo=open("ECC_P384_GEN.txt","r")
for linea in archivo.readlines():
    if "Qx = " in linea:#Lee el punto X del archivo
        fQx = linea.lstrip("Qx = ")
        listQX.append(fQx.rstrip("\n"))
    elif "Qy = " in linea:#Lee el punto Y del archivo
        fQy = linea.lstrip("Qy = ")
        listQY.append(fQy.rstrip("\n"))
    elif "Msg = " in linea:#Lee los mensajes del archivo
        m = linea.lstrip("Msg = ")
        listMsg.append(m.rstrip("\n"))
    elif "R = " in linea:#Lee la firma R del archivo
        fr = linea.lstrip("R = ")
        listR.append(fr.rstrip("\n"))
    elif "S = " in linea:#Lee la firma s del archivo
        fs = linea.lstrip("S = ")
        listS.append(fs.rstrip("\n"))
    elif "d = " in linea:#Lee el parametro Y del archivo
        fd = linea.lstrip("d = ")
        listd.append(fd.rstrip("\n"))
archivo.close()

for i in range(0, 4):
    for i in range(0, len(listMsg)):
        Msg = bytearray.fromhex(listMsg[i])
        Qx = int(listQX[i],16)
        Qy = int(listQY[i],16)
        d = int(listd[i],16)
        
        key=ECC.construct(curve="P-384",d=d,point_x= Qx,point_y= Qy)#llave privada
        timeI=time()
        h=SHA3_512.new(Msg)#Ocupamos este hash porque ECDSA pide más seguridad
        firma=DSS.new(key,"fips-186-3")
        sign_fir=firma.sign(h)
        timeF=time()
        timeGenECC_384.append(timeF-timeI)
        #print(sign_fir.hex(),"\n")

#VERIFICAR FIRMA
listQX=[]#Lista del punto X
listQY=[]#Lista del punto Y
listMsg=[]#Lista de los mensajes
listR=[]#Lista de firmas R
listS=[]#Lista de firmas S

archivo=open("ECC_P384_VER.txt","r")
for linea in archivo.readlines():
    if "Qx = " in linea:#Lee el punto X del archivo
        fQx = linea.lstrip("Qx = ")
        listQX.append(fQx.rstrip("\n"))
    elif "Qy = " in linea:#Lee el punto Y del archivo
        fQy = linea.lstrip("Qy = ")
        listQY.append(fQy.rstrip("\n"))
    elif "Msg = " in linea:#Lee los mensajes del archivo
        m = linea.lstrip("Msg = ")
        listMsg.append(m.rstrip("\n"))
    elif "R = " in linea:#Lee la firma R del archivo
        fr = linea.lstrip("R = ")
        listR.append(fr.rstrip("\n"))
    elif "S = " in linea:#Lee la firma s del archivo
        fs = linea.lstrip("S = ")
        listS.append(fs.rstrip("\n"))
archivo.close()

for i in range(0, 4):
    for i in range(0, len(listMsg)):
        Msg = bytearray.fromhex(listMsg[i])
        Qx = int(listQX[i],16)
        Qy = int(listQY[i],16)
        R = bytearray.fromhex(listR[i])
        S = bytearray.fromhex(listS[i])

        key=ECC.construct(curve="P-384",point_x= Qx,point_y= Qy)#llave pública
        timeI=time()
        verifica=DSS.new(key,"fips-186-3")
        h=SHA256.new(Msg)
        try:
            verifica.verify(h,R+S)
            #print("Verificar firma:")
            #print("Firma valida")
            ver=True
        except(ValueError, TypeError):
            #print("Firma no valida")
            ver=False
        timeF=time()
        timeVerECC_384.append(timeF-timeI)  

    
#---------------------------------RESULTADOS ECDSA--------------------------
columnsECDSA = ['ECDSAGEN_P521','ECDSAVER_P521','ECDSAGEN_P384','ECDSAVER_P384']
tmp_promECDSA=[statistics.mean(timeGenECC_521), statistics.mean(timeVerECC_521), statistics.mean(timeGenECC_384), statistics.mean(timeVerECC_384)]
print('ECDSAGEN_P521: ', tmp_promECDSA[0],
      '\nECDSAVER_P521: ', tmp_promECDSA[1],
      '\nECDSAGEN_P384: ', tmp_promECDSA[2],
      '\nECDSAVER_P384: ', tmp_promECDSA[3])
print("\n\n")

#ESCRITURA DE RESULTADOS DE SHA EN EXCEL
dataECDSA = {'ECDSAGEN_P521': timeGenECC_521,
        'ECDSAVER_P521': timeVerECC_521,
             'ECDSAGEN_P384': timeGenECC_384,
        'ECDSAVER_P384': timeVerECC_384}

df = pd.DataFrame(dataECDSA, columns = columnsECDSA)
df.to_excel('EjecucionECDSA.xlsx', sheet_name='ECDSA')
    
    

    
    
    
    
    
    

