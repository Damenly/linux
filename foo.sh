for l in $(cat ~/workspace/surface/configs/surface-5.15.config); do

    for c in  "$(echo $l | grep CONFIG)"; do
        s="$(echo $c  | sed  '/^$/d')"

        [ -z "$s" ] && continue
        grep -q $s .config || echo $c
    done

done
