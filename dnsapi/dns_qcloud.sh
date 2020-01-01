#!/usr/bin/env sh

#DNS API For QCloud (Tencent Cloud CN)
#Author: Haitao Huang
#Report Bugs here: https://github.com/huanght1997/acme.sh

#QCloud_SecretKey="xxxxx"
#QCloud_SecretId="xxxxx"

QCloud_API="https://cns.api.qcloud.com/v2/index.php"
QCloud_APIHost="cns.api.qcloud.com/v2/index.php"

########  Public functions #####################

#Usage: add _acme-challenge.www.domain.com   "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs"
dns_qcloud_add() {
  fulldomain=$1
  txtvalue=$2

  QCloud_SecretId="${QCloud_SecretId:-$(_readaccountconf_mutable QCloud_SecretId)}"
  QCloud_SecretKey="${QCloud_SecretKey:-$(_readaccountconf_mutable QCloud_SecretKey)}"
  if [ -z "$QCloud_SecretId" ] || [ -z "$QCloud_SecretKey" ]; then
    QCloud_SecretId=""
    QCloud_SecretKey=""
    _err "You don't specify QCloud SecretKey and SecretId yet."
    _err "Please create your API keys and try again."
    return 1
  fi

  #save the credentials to the account conf file.
  _saveaccountconf_mutable QCloud_SecretId "$QCloud_SecretId"
  _saveaccountconf_mutable QCloud_SecretKey "$QCloud_SecretKey"

  _debug "First detect the root zone"
  if ! _qc_get_root "$fulldomain"; then
    _err "invalid domain"
    return 1
  fi
  _debug _domain "$_domain"
  _debug _sub_domain "$_sub_domain"

  _debug "Add txt records"
  _qc_record_create "$_domain" "$_sub_domain" "$txtvalue"
  _qc_rest "RecordCreate" "additional-handle"
  message="$(echo "$response" | _egrep_o "\"message\":\"[^\"]*\"" | cut -d : -f 2 | tr -d \")"
  if [ -z "$message" ]; then
    _debug "Add txt records success."
  elif _contains "$message" "(8104104)"; then
    # Record has been added, regard it as success.
    _debug "A same txt record has been added."
  else
    _err "$message"
    return 1
  fi
}

#Usage: rm fulldomain txtvalue
dns_qcloud_rm() {
  fulldomain=$1
  txtvalue=$2

  QCloud_SecretId="${QCloud_SecretId:-$(_readaccountconf_mutable QCloud_SecretId)}"
  QCloud_SecretKey="${QCloud_SecretKey:-$(_readaccountconf_mutable QCloud_SecretKey)}"

  _debug "First detect the root zone"
  if ! _qc_get_root "$fulldomain"; then
    _err "invalid domain"
    return 1
  fi

  _qc_record_delete_do "$_domain" "$_sub_domain" "$txtvalue"
}

####################  Private functions below ##################################
#_acme-challenge.www.domain.com
#returns
# _sub_domain=_acme-challenge.www
# _domain=domain.com
_qc_get_root() {
  # Get the domain list in the account and store in $response.
  _qc_domain_list
  if ! _qc_rest "DomainList" "silent"; then
    return 1
  fi

  # Now check whether the domain is in $reponse.
  domain=$1
  i=1
  p=1
  while true; do
    # Try to get part of the domain
    h=$(printf "%s" "$domain" | cut -d . -f $i-100)
    _debug2 h "$h"

    if ! _contains "$h" "\."; then
      #not valid
      return 1
    fi

    if [ -z "$h" ]; then
      #not valid
      return 1
    fi

    if _contains "$response" "\"name\":\"$h\""; then
      _domain=$h
      _sub_domain=$(printf "%s" "$domain" | cut -d . -f 1-$p)
      return 0
    fi

    p=$i
    i=$(_math "$i" + 1)
  done

  return 1
}

#Usage: purpose [auto-handle]
_qc_rest() {
  signature=$(printf "%s" "GET${QCloud_APIHost}?$query" | _hmac "sha256" "$(printf "%s" "$QCloud_SecretKey" | _hex_dump | tr -d " ")" | _base64)
  signature=$(_qc_urlencode "$signature")
  url="$QCloud_API?$query&Signature=$signature"

  _debug "REST URL: $url"
  if ! response="$(_get "$url")"; then
    _err "Error <$1>"
    return 1
  fi

  _debug2 "Response: $response"
  if [ -z "$2" ]; then
    message="$(echo "$response" | _egrep_o "\"message\":\"[^\"]*\"" | cut -d : -f 2 | tr -d \")"
    if [ "$message" ]; then
      _err "$message"
      return 1
    fi
  fi
}

_qc_urlencode() {
  _str="$1"
  _str_len=${#_str}
  _u_i=1
  while [ "$_u_i" -le "$_str_len" ]; do
    # Get the "$_u_i"-th character in $_str.
    _str_c="$(printf "%s" "$_str" | cut -c "$_u_i")"
    case $_str_c in
      [a-zA-Z0-9.~_-])
        printf "%s" "$_str_c"
        ;;
      *)
        printf "%%%02X" "'$_str_c"
        ;;
    esac
    _u_i="$(_math "$_u_i" + 1)"
  done
}

# Generate random number
_qc_nonce() {
  hexnum=$(_head_n 1 </dev/urandom | _digest "sha256" hex | cut -c 1-8)
  printf "%u" 0x"$hexnum"
}

_qc_timestamp() {
  date +%s
}

_qc_domain_list() {
  query=""
  query=$query"Action=DomainList"
  query=$query"&Nonce=$(_qc_nonce)"
  query=$query"&SecretId="$QCloud_SecretId
  query=$query"&SignatureMethod=HmacSHA256"
  query=$query"&Timestamp=$(_qc_timestamp)"
  query=$query"&length=100"
}

#Usage: domain [sub_domain]
_qc_record_list() {
  query=""
  query=$query"Action=RecordList"
  query=$query"&Nonce=$(_qc_nonce)"
  query=$query"&SecretId="$QCloud_SecretId
  query=$query"&SignatureMethod=HmacSHA256"
  query=$query"&Timestamp=$(_qc_timestamp)"
  query=$query"&domain="$1
  if [ -n "$2" ]; then
    query=$query"&subDomain="$2
  fi
}

#Usage: domain sub_domain txtvalue [recordLine]
_qc_record_create() {
  if [ -z "$4" ]; then
    recordLine="默认"
  else
    recordLine="$4"
  fi
  query=""
  query=$query"Action=RecordCreate"
  query=$query"&Nonce=$(_qc_nonce)"
  query=$query"&SecretId="$QCloud_SecretId
  query=$query"&SignatureMethod=HmacSHA256"
  query=$query"&Timestamp=$(_qc_timestamp)"
  query=$query"&domain="$1
  query=$query"&recordLine="$recordLine
  query=$query"&recordType=TXT"
  query=$query"&subDomain="$2
  query=$query"&value="$3
}

#Usage:domain sub_domain txtvalue
_qc_record_delete_do() {
  _qc_record_list "$1" "$2"
  if ! _qc_rest "RecordList" "silent"; then
    return 1
  fi

  _id_list=$(printf "%s" "$response" | _egrep_o "\"id\":[0-9]+.*\"value\":\"$3\"" | cut -d , -f 1 | cut -d : -f 2)
  for _id in $_id_list; do
    query=""
    query=$query"Action=RecordDelete"
    query=$query"&Nonce=$(_qc_nonce)"
    query=$query"&SecretId="$QCloud_SecretId
    query=$query"&SignatureMethod=HmacSHA256"
    query=$query"&Timestamp=$(_qc_timestamp)"
    query=$query"&domain="$1
    query=$query"&recordId="$_id
    _qc_rest "RecordDelete" "silent"
  done
}
