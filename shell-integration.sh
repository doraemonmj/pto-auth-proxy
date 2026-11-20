# Sourced by the generated env.sh; compatible with Bash and Zsh.
# Variable names in eval are from fixed lists below, never from user input.

_pto_proxy_is_ours() {
    case "$1" in
        "http://${_PTO_PROXY_USER}:"*"@${_PTO_PROXY_HOST}:${_PTO_PROXY_HTTP_PORT}"|\
        "socks5h://${_PTO_PROXY_USER}:"*"@${_PTO_PROXY_HOST}:${_PTO_PROXY_SOCKS_PORT}") return 0 ;;
    esac
    return 1
}

_pto_proxy_switch() {
    local _pto_action=$1 _pto_default=${2:-} _pto_name _pto_value _pto_present
    local _pto_secret _pto_bypass _pto_item _pto_trace=0
    case $- in *x*) _pto_trace=1; set +x ;; esac
    if [ "$_pto_action" = on ]; then
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
    if [ "$_pto_action" = on ]; then
        if [ "${_PTO_PROXY_ACTIVE:-0}" != 1 ]; then
            for _pto_name in HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy NO_PROXY no_proxy; do
                eval '_pto_value=${'"$_pto_name"'-}; _pto_present=${'"$_pto_name"'+yes}'
                # A child shell must not save inherited PTO URLs as its original environment.
                if _pto_proxy_is_ours "$_pto_value"; then _pto_present=; _pto_value=; fi
                eval '_PTO_SAVED_'"$_pto_name"'=$_pto_value; _PTO_SET_'"$_pto_name"'=$_pto_present'
            done
        fi
        if ! _pto_secret=$(cat -- "${XDG_CONFIG_HOME:-$HOME/.config}/pto-auth-proxy/secret-uri"); then
            [ "$_pto_trace" = 0 ] || set -x
            return 1
        fi
        for _pto_name in HTTP_PROXY HTTPS_PROXY http_proxy https_proxy; do
            export "$_pto_name=http://${_PTO_PROXY_USER}:${_pto_secret}@${_PTO_PROXY_HOST}:${_PTO_PROXY_HTTP_PORT}"
        done
        export ALL_PROXY="socks5h://${_PTO_PROXY_USER}:${_pto_secret}@${_PTO_PROXY_HOST}:${_PTO_PROXY_SOCKS_PORT}"
        export all_proxy="$ALL_PROXY"
        _pto_bypass=,${NO_PROXY-${no_proxy-}},
        # Explicit on overrides a catch-all bypass while off restores the original.
        while [ "${_pto_bypass#,\*,}" != "$_pto_bypass" ] || [ "${_pto_bypass//,\*,/,}" != "$_pto_bypass" ]; do
            _pto_bypass=${_pto_bypass//,\*,/,}
        done
        _pto_bypass=${_pto_bypass#,}
        _pto_bypass=${_pto_bypass%,}
        for _pto_item in localhost 127.0.0.0/8 ::1 169.254.169.254 192.168.0.0/16 10.0.0.0/8; do
            case ",$_pto_bypass," in
                *",$_pto_item,"*) ;;
                *) _pto_bypass="${_pto_bypass:+$_pto_bypass,}$_pto_item" ;;
            esac
        done
        export NO_PROXY="$_pto_bypass" no_proxy="$_pto_bypass"
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
    unset _pto_secret _pto_value
    [ "$_pto_trace" = 0 ] || set -x
    return 0
}

pto-auth-proxy() {
    case "${1:-}" in
        on|off)
            if [ "$#" -gt 2 ] || { [ "$#" = 2 ] && [ "$2" != --default ]; }; then
                echo 'usage: pto-auth-proxy on|off [--default]' >&2; return 2
            fi
            _pto_proxy_switch "$@" || return
            echo "Proxy environment: $1 (current shell); existing applications keep their environment."
            ;;
        *) command "$_PTO_PROXY_COMMAND" "$@" ;;
    esac
}

_pto_proxy_load_default() {
    local _pto_mode=proxy
    if [ -r "${XDG_CONFIG_HOME:-$HOME/.config}/pto-auth-proxy/default-mode" ]; then
        IFS= read -r _pto_mode <"${XDG_CONFIG_HOME:-$HOME/.config}/pto-auth-proxy/default-mode"
    fi
    case "$_pto_mode" in
        proxy)
            # A stopped or logged-out user still gets working shell controls.
            _pto_proxy_switch on 2>/dev/null || _pto_proxy_switch off
            ;;
        direct) _pto_proxy_switch off ;;
        *) echo 'pto-auth-proxy: invalid default-mode; use on/off --default' >&2 ;;
    esac
}
_pto_proxy_load_default
