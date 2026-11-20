# Sourced by the generated env.sh; compatible with Bash and Zsh.
# Variable names in eval are from fixed lists below, never from user input.

# Defaults keep pre-auto env.sh hooks sourceable after an application upgrade.
_PTO_PROXY_AUTO_HTTP_PORT=${_PTO_PROXY_AUTO_HTTP_PORT:-20811}
_PTO_PROXY_AUTO_SOCKS_PORT=${_PTO_PROXY_AUTO_SOCKS_PORT:-20810}

_pto_proxy_is_ours() {
    case "$1" in
        "http://${_PTO_PROXY_USER}:"*"@${_PTO_PROXY_HOST}:${_PTO_PROXY_HTTP_PORT}"|\
        "http://${_PTO_PROXY_USER}:"*"@${_PTO_PROXY_HOST}:${_PTO_PROXY_AUTO_HTTP_PORT}"|\
        "socks5h://${_PTO_PROXY_USER}:"*"@${_PTO_PROXY_HOST}:${_PTO_PROXY_SOCKS_PORT}"|\
        "socks5h://${_PTO_PROXY_USER}:"*"@${_PTO_PROXY_HOST}:${_PTO_PROXY_AUTO_SOCKS_PORT}") return 0 ;;
    esac
    return 1
}

_pto_proxy_switch() {
    local _pto_action=$1 _pto_default=${2:-} _pto_name _pto_value _pto_present
    local _pto_secret _pto_bypass _pto_item _pto_trace=0 _pto_http_port _pto_socks_port
    case $- in *x*) _pto_trace=1; set +x ;; esac
    if [ "$_pto_action" = on ] || [ "$_pto_action" = auto ]; then
        if ! command "$_PTO_PROXY_COMMAND" shell-ready; then
            [ "$_pto_trace" = 0 ] || set -x
            return 1
        fi
    fi
    if [ "$_pto_default" = --default ]; then
        # Persist before changing the shell, so a write failure leaves it alone.
        if ! command "$_PTO_PROXY_COMMAND" "$_pto_action" --default >/dev/null; then
            [ "$_pto_trace" = 0 ] || set -x
            return 1
        fi
    fi
    if [ "$_pto_action" != restore ] && [ "${_PTO_PROXY_ACTIVE:-0}" != 1 ]; then
        for _pto_name in HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy NO_PROXY no_proxy; do
            eval '_pto_value=${'"$_pto_name"'-}; _pto_present=${'"$_pto_name"'+yes}'
            if _pto_proxy_is_ours "$_pto_value"; then _pto_present=; _pto_value=; fi
            eval '_PTO_SAVED_'"$_pto_name"'=$_pto_value; _PTO_SET_'"$_pto_name"'=$_pto_present'
        done
    fi
    if [ "$_pto_action" = on ] || [ "$_pto_action" = auto ]; then
        _pto_http_port=$_PTO_PROXY_HTTP_PORT
        _pto_socks_port=$_PTO_PROXY_SOCKS_PORT
        if [ "$_pto_action" = auto ]; then
            _pto_http_port=$_PTO_PROXY_AUTO_HTTP_PORT
            _pto_socks_port=$_PTO_PROXY_AUTO_SOCKS_PORT
        fi
        if ! _pto_secret=$(cat -- "${XDG_CONFIG_HOME:-$HOME/.config}/pto-auth-proxy/secret-uri"); then
            [ "$_pto_trace" = 0 ] || set -x
            return 1
        fi
        for _pto_name in HTTP_PROXY HTTPS_PROXY http_proxy https_proxy; do
            export "$_pto_name=http://${_PTO_PROXY_USER}:${_pto_secret}@${_PTO_PROXY_HOST}:${_pto_http_port}"
        done
        export ALL_PROXY="socks5h://${_PTO_PROXY_USER}:${_pto_secret}@${_PTO_PROXY_HOST}:${_pto_socks_port}"
        export all_proxy="$ALL_PROXY"
        _pto_bypass=${NO_PROXY-${no_proxy-}}
        if [ "$_pto_action" = on ]; then
            # A manual proxy override must not keep external-domain bypasses.
            _pto_bypass=
        elif [ "${_PTO_PROXY_MODE:-}" = off ] || [ "${_PTO_PROXY_MODE:-}" = on ]; then
            if [ "${_PTO_SET_NO_PROXY:-}" = yes ]; then
                _pto_bypass=${_PTO_SAVED_NO_PROXY-}
            else
                _pto_bypass=${_PTO_SAVED_no_proxy-}
            fi
        fi
        _pto_bypass=,$_pto_bypass,
        # Explicit on overrides a catch-all bypass while restore preserves the original.
        while [ "${_pto_bypass#,\*,}" != "$_pto_bypass" ] || [ "${_pto_bypass//,\*,/,}" != "$_pto_bypass" ]; do
            _pto_bypass=${_pto_bypass//,\*,/,}
        done
        _pto_bypass=${_pto_bypass#,}
        _pto_bypass=${_pto_bypass%,}
        for _pto_item in localhost 127.0.0.1 127.0.0.0/8 ::1 169.254.169.254 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12; do
            case ",$_pto_bypass," in
                *",$_pto_item,"*) ;;
                *) _pto_bypass="${_pto_bypass:+$_pto_bypass,}$_pto_item" ;;
            esac
        done
        export NO_PROXY="$_pto_bypass" no_proxy="$_pto_bypass"
        _PTO_PROXY_ACTIVE=1
    elif [ "$_pto_action" = off ]; then
        unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
        export NO_PROXY='*' no_proxy='*'
        _PTO_PROXY_ACTIVE=1
    else
        for _pto_name in HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy NO_PROXY no_proxy; do
            if [ "${_PTO_PROXY_ACTIVE:-0}" = 1 ]; then
                eval '_pto_value=${_PTO_SAVED_'"$_pto_name"'-}; _pto_present=${_PTO_SET_'"$_pto_name"'-}'
                if [ "$_pto_present" = yes ]; then
                    export "$_pto_name=$_pto_value"
                else
                    unset "$_pto_name"
                fi
                unset "_PTO_SAVED_$_pto_name" "_PTO_SET_$_pto_name"
            else
                eval '_pto_value=${'"$_pto_name"'-}'
                if _pto_proxy_is_ours "$_pto_value"; then unset "$_pto_name"; fi
            fi
        done
        _PTO_PROXY_ACTIVE=0
    fi
    _PTO_PROXY_MODE=$_pto_action
    unset _pto_secret _pto_value
    [ "$_pto_trace" = 0 ] || set -x
    return 0
}

pto-auth-proxy() {
    case "${1:-}" in
        auto|on|off|restore)
            if [ "$#" -gt 2 ] || { [ "$#" = 2 ] && [ "$2" != --default ]; }; then
                echo 'usage: pto-auth-proxy auto|on|off [--default], or restore' >&2; return 2
            fi
            if [ "$1" = restore ] && [ "$#" != 1 ]; then
                echo 'restore does not change the saved default' >&2; return 2
            fi
            _pto_proxy_switch "$@" || return
            echo "Proxy environment: $1 (current shell); existing applications keep their environment."
            ;;
        *) command "$_PTO_PROXY_COMMAND" "$@" ;;
    esac
}

_pto_proxy_load_default() {
    local _pto_mode=auto
    if [ -r "${XDG_CONFIG_HOME:-$HOME/.config}/pto-auth-proxy/default-mode" ]; then
        IFS= read -r _pto_mode <"${XDG_CONFIG_HOME:-$HOME/.config}/pto-auth-proxy/default-mode"
    fi
    case "$_pto_mode" in
        auto|proxy)
            # A stopped/logged-out user still gets shell controls. Preserve any
            # original external proxy rather than silently selecting a new route.
            if [ "$_pto_mode" = proxy ]; then _pto_mode=on; fi
            _pto_proxy_switch "$_pto_mode" 2>/dev/null || _pto_proxy_switch restore
            ;;
        direct) _pto_proxy_switch off ;;
        *) echo 'pto-auth-proxy: invalid default-mode; use auto/on/off --default' >&2 ;;
    esac
}
_pto_proxy_load_default
