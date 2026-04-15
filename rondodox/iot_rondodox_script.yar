rule iot_rondodox_script {
    meta:
        description = "Detects the rondodox script"
        author = "jcfg"
        date = "2025-11-06"
        hash = "81d8941016dcc0dc42f57c6f4948c8a837b9c8c9ecc37908dfb092ac2dcf8cae"
    strings:
        $s0 = "(chmod 777 rondo || busybox chmod 777 rondo) || (chmod +x rondo || busybox chmod +x rondo)" ascii nocase
	$s1 = "rm -rf rondo" ascii nocase
	$s2 = "chmod 777 rondo||busybox chmod 777 rondo" ascii nocase
	$s3 = "./rondo" ascii nocase

    condition:
        filesize < 15KB and
        2 of them
}
