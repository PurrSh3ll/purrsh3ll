xmlwrap() {
    if [[ $# -lt 1 ]]; then
        echo "Usage: xmlwrap <command> [args...]"
        return 1
    fi

    cmd="$1"
    shift

    # Allow `xmlwrap sudo nmap …`: xmlwrap is a shell function, so `sudo xmlwrap`
    # can't resolve it. Instead we accept a leading `sudo`, strip it here, and
    # re-apply it only to the nmap invocation (raw-socket scans like -sS/-sU need
    # root). The wrapper itself keeps running as the normal user.
    USE_SUDO=""
    if [[ "$cmd" == "sudo" ]]; then
        USE_SUDO="sudo"
        cmd="$1"
        shift
    fi

    if [[ "$cmd" != "nmap" ]]; then
        echo "xmlwrap: supported only for nmap"
        return 1
    fi

    WEBMAP_DIR="${${(%):-%x}:A:h:h:h}/appmodules/Cyb3rCollector/webmap"
    mkdir -p "$WEBMAP_DIR"

    TS=$(date +"%Y%m%d-%H%M%S")
    OUTFILE="$WEBMAP_DIR/nmap-$TS.xml"

    USER_OX=""
    USER_OA=""

    args=("$@")

    # szukamy -oX <plik> oraz -oA <base>
    for ((i=0; i<${#args[@]}; i++)); do
        if [[ "${args[$i]}" == "-oX" ]]; then
            USER_OX="${args[$((i+1))]}"
        fi
        if [[ "${args[$i]}" == "-oA" ]]; then
            USER_OA="${args[$((i+1))]}"
        fi
    done

    # jeśli user NIE podał ani -oX ani -oA, dopisujemy własny -oX
    if [[ -z "$USER_OX" && -z "$USER_OA" ]]; then
        $USE_SUDO /usr/bin/nmap "$@" -oX "$OUTFILE"
        STATUS=$?
        # Under sudo nmap writes OUTFILE as root; hand it back to the invoking
        # user so the app can read/clean it (sudo credentials are still cached).
        if [[ -n "$USE_SUDO" && -f "$OUTFILE" ]]; then
            sudo chown "$(id -un):$(id -gn)" "$OUTFILE"
        fi
        return $STATUS
    fi

    # jeśli user podał -oX -
    if [[ "$USER_OX" == "-" ]]; then
        $USE_SUDO /usr/bin/nmap "$@" | tee "$OUTFILE"
        STATUS=${PIPESTATUS[0]}
        echo "[xmlwrap] Saved XML output to: $OUTFILE"
        return $STATUS
    fi

    # normalne wykonanie nmap
    $USE_SUDO /usr/bin/nmap "$@"
    STATUS=$?

    # jeśli user podał -oX <plik>
    if [[ -n "$USER_OX" && "$USER_OX" != "-" ]]; then
        if [[ -f "$USER_OX" ]]; then
            cp "$USER_OX" "$OUTFILE"
            echo "[xmlwrap] Copied XML output to: $OUTFILE"
        else
            echo "[xmlwrap] Warning: XML file not found: $USER_OX"
        fi
    fi

    # jeśli user podał -oA <base> -> kopiujemy base.xml
    if [[ -n "$USER_OA" ]]; then
        XMLFILE="${USER_OA}.xml"
        if [[ -f "$XMLFILE" ]]; then
            cp "$XMLFILE" "$OUTFILE"
            echo "[xmlwrap] Copied XML output from -oA to: $OUTFILE"
        else
            echo "[xmlwrap] Warning: XML file from -oA not found: $XMLFILE"
        fi
    fi

    return $STATUS
}