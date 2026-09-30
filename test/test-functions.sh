FILE=$1

assert_num_funcs() {
	local num_funcs=$(objdump -t "$FILE" | awk '$3 == "F" && $4 ~ /^\.text($|\.)/ { count++ } END { print count + 0 }')

	if [[ $num_funcs != $1 ]]; then
		echo "$FILE: assertion failed: file has $num_funcs funcs, expected $1" 1>&2
		exit 1
	fi

	return 0
}
