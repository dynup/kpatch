FILE=$1

assert_num_funcs() {
	local num_funcs=$(nm $FILE | grep -i " t " | wc -l)

	if [[ $num_funcs != $1 ]]; then
		echo "$FILE: assertion failed: file has $num_funcs funcs, expected $1" 1>&2
		exit 1
	fi

	return 0
}
