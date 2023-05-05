echo ${args} | tr -d ' ' | tr ',' '\012' |
	awk -v atomic=${atomic} \
	    -v name_op=${name} \
	    -v ret=${ret} \
	    -v oldnew=${docbook_oldnew} \
	    -v acqrel=${acqrel} \
	    -v basefuncname=arch_${atomic}_${pfx}${name}${sfx} '
	BEGIN {
		print "/**";
		sfxord = "_" acqrel;
		if (acqrel == "full")
			sfxord = "";
		print " * " basefuncname sfxord " - Atomic " name_op " with " acqrel " ordering";
		longname["add"] = "add";
		longname["sub"] = "subtract";
		longname["inc"] = "increment";
		longname["dec"] = "decrement";
		longname["and"] = "AND";
		longname["andnot"] = "complement then AND";
		longname["or"] = "OR";
		longname["xor"] = "XOR";
		longname["xchg"] = "exchange";
		longname["add_negative"] = "add";
		desc["i"] = "value to " longname[name_op];
		desc["v"] = "pointer of type " atomic "_t";
		desc["old"] = "desired old value to match";
		desc["new"] = "new value to put in";
		opmod = "with";
		if (name_op == "add")
			opmod = "to";
		else if (name_op == "sub")
			opmod = "from";
	}

	{
		print " * @" $1 ": " desc[$1];
		have[$1] = 1;
	}

	END {
		print " *";
		if (name_op ~ /cmpxchg/) {
			print " * Atomically compares @new to *@v, and if equal,";
			print " * stores @new to *@v, providing " acqrel " ordering.";
		} else if (have["i"]) {
			print " * Atomically " longname[name_op] " @i " opmod " @v using " acqrel " ordering.";
		} else {
			print " * Atomically " longname[name_op] " @v using " acqrel " ordering.";
		}
		if (name_op ~ /cmpxchg/ && ret == "bool") {
			print " * Returns @true if the cmpxchg operation succeeded,";
			print " * and false otherwise.  Either way, stores the old";
			print " * value of *@v to *@old.";
		} else if (name_op == "cmpxchg") {
			print " * Returns the old value *@v regardless of the result of";
			print " * the comparison.  Therefore, if the return value is not";
			print " * equal to @old, the cmpxchg operation failed.";
		} else if (name_op == "xchg") {
			print " * Return old value.";
		} else if (name_op == "add_negative") {
			print " * Return @true if the result is negative, or @false when"
			print " * the result is greater than or equal to zero.";
		} else {
			print " * Return " oldnew " value.";
		}
		print " */";
	}'
