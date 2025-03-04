<?php
$flag = "FLAG{secret_data}";

// Step 1: Double Base64 Encoding
$base64_once = base64_encode($flag);
$base64_twice = base64_encode($base64_once);

echo "Double Base64: $base64_twice\n";

// Step 2: Check if Ends with '=='
if (substr($base64_twice, -2) !== "==") {
    echo "Padding is incorrect, adding junk characters...\n";

    // Step 3: Add junk characters using iconv
    $junk = iconv("UTF-8", "CSISO2022KR", "XXXX") . $flag;
    $base64_once = base64_encode($junk);
    $base64_twice = base64_encode($base64_once);

    echo "Modified Double Base64: $base64_twice\n";
}

// Step 4: Apply convert.quoted-printable-encode
$quoted_encoded = quoted_printable_encode($base64_twice);
echo "Quoted-printable Encoded: $quoted_encoded\n";

/* 
Output: 
    Double Base64: Umt4QlIzdHpaV055WlhSZlpHRjBZWDA9
    Padding is incorrect, adding junk characters...
    Modified Double Base64: V0ZoWVdFWk1RVWQ3YzJWamNtVjBYMlJoZEdGOQ==
    Quoted-printable Encoded: V0ZoWVdFWk1RVWQ3YzJWamNtVjBYMlJoZEdGOQ=3D=3D
*/
?>