#!/bin/sh

if [ -z "$DPATH" ]; then
    if [ -z "$1" ]; then
    	echo "Installation path not defined (running interactively ?)";
	echo "If this is the case, run $0 <path>";
	exit 1;
    else
	DPATH=$1;
	USE_SSL=1;

	ECHO='echo';
	test -z `echo -n` && ECHO='echo -n';

	. tools/ssl-search.sh
    fi
    
    if [ ! -d "$DPATH" ]; then
    	echo "Invalid installation path.";
	exit 1;
    fi;
fi

CERT_DAYS=365
REBUILD_CRT="1"
if [ -n "$USE_SSL" ]; then

	if [ -r "$DPATH/ircd.crt" ]; then
		echo " ";
		echo "*** You already have an SSL certificate . . .";
		echo " ";

		FOO=""
		runonce=""
		while [ -z "$FOO" ] ; do
		    FOO="No"
		    echo ""
		    echo "Do you want to rebuild your certificate ?";
		    $ECHO "[$FOO] -> $c"
		    if [ -z "$AUTO_CONFIG" -o -n "$runonce" ] ; then
			read cc
			runonce=Yes
		    else
			cc=""
		    fi
		    if [ -z "$cc" ] ; then
			cc=$FOO
		    fi
		    case "$cc" in
			[Yy]*)
			    REBUILD_CRT="1"
			    ;;
			[Nn]*)
			    REBUILD_CRT=""
			    ;;
			*)
			    echo ""
			    echo "You need to enter either Yes or No here..."
			    echo ""
			    FOO=""
			    ;;
		    esac
		done
	fi
	
	if [ -n "$REBUILD_CRT" ]; then
		echo " ";
		echo "*** Building a new SSL certificate for your server.";

		FOO=""
		runonce=""
		while [ -z "$FOO" ] ; do
		    FOO="$CERT_DAYS"
		    echo " "
		    echo "How many days will your certificate last ?"
		    echo " "
		    $ECHO "[$FOO] -> $c"
		    if [ -z "$AUTO_CONFIG" -o -n "$runonce" -o -z "$SERVICES_NAME" ] ; then
			read cc
			runonce=Yes
		    else
			cc=""
		    fi
		    if [ -z "$cc" ] ; then
			cc=$FOO
		    fi
		    case "$cc" in
		        *)
		            CERT_DAYS="$cc"
		    esac
		done
	
		$openssl req -new -x509 -days $CERT_DAYS -nodes \
			-config ircdssl.cnf -out "$DPATH/ircd.crt" \
			-keyout "$DPATH/ircd.key" $RNDF
		$openssl x509 -subject -dates -fingerprint -noout \
			-in "$DPATH/ircd.crt"

	fi

	echo " "
	echo "*** SSL certificate step done."
	echo " "
fi
