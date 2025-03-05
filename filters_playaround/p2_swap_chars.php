<?php

function debug_output($step, $data, $raw_hex = false) {
    echo "[$step]: ";
    if ($raw_hex) {
        echo bin2hex($data) . PHP_EOL;

    } else {
        echo $data . PHP_EOL;
    }
}

function to_byte_format($data) {
    $result = '';
    for ($i = 0; $i < strlen($data); $i++) {
        $char = $data[$i];
        $ascii = ord($char);
        // If ASCII is printable, keep it, otherwise show as hex
        if ($ascii >= 32 && $ascii <= 126) {
            $result .= $char;
        } else {
            $result .= sprintf("\\x%02x", $ascii);
        }
    }
    return $result;
}

// Step 1: Start with an assumed double base64-encoded string
$input = "abcdefghij==";
debug_output("Step 1 - Initial Formatted String", $input);

// Step 2: Byte alignment (convert.quoted-printable-encode + convert.iconv.L1.utf7)
$temp1 = quoted_printable_encode($input);
debug_output("Step 2.1 - Quoted-Printable Encode 1", $temp1);
$temp2 = quoted_printable_encode($temp1);
debug_output("Step 2.2 - Quoted-Printable Encode 2", $temp2);
$temp3 = iconv("UTF-8", "UTF-7", $temp2);
debug_output("Step 2.3 - UTF-7 Encode 1", $temp3);
$temp4 = iconv("UTF-8", "UTF-7", $temp3);
debug_output("Step 2.4 - UTF-7 Encode 2", $temp4);
$temp5 = iconv("UTF-8", "UTF-7", $temp4);
debug_output("Step 2.5 - UTF-7 Encode 3", $temp5);
$alighned = iconv("UTF-8", "UTF-7", $temp5);
debug_output("Step 2.6 - UTF-7 Encode 4", $alighned);

// Step 3: Apply R2 (convert.iconv.CSUNICODE.CSUNICODE) 
$r2 = iconv("CSUNICODE", "CSUNICODE", $alighned);
debug_output("Step 3 - R2 should append <0xff><0xfe> (fffe in hex) for", $alighned);
debug_output("Step 3 - The HEX Pre-R2 input (Before applying CSUNICODE)", $alighned, true);
debug_output("Step 3 - CSUNICODE applied (expect <0xff><0xfe>)", $r2, true);
$formatted = to_byte_format($r2);
debug_output("Step 3 - CSUNICODE applied (Formatted Byte Output)", $formatted);

// Step 4: Apply R4 (UCS-4LE.10646-1:1993) - Swap every 4 bytes
$r4 = iconv("UCS-4LE", "10646-1:1993", $r2);
debug_output("Step 4 - R4 should swap chunks of 4 for", $formatted);
debug_output("Step 4 - The HEX Pre-R4 input (Before applying UCS-4LE.10646-1:1993)", $r2);
debug_output("Step 4 - R4 Applied", $r4, true);
$formatted = to_byte_format($r4);
debug_output("Step 4 - 10646-1:1993 Applied (Formatted Byte Output)", $formatted);

// Step 5: Apply Base64-decode and encode
$b64_decode = base64_decode($r4);
$b64_encode = base64_encode($b64_decode);
debug_output("Step 5 - Base64 Decode+Encode to recover string format", $b64_encode);

// Step 6: Apply R4 again
$r4_again = iconv("UCS-4LE", "10646-1:1993", $b64_encode);
debug_output("Step 6 - R4 should swap chunks of 4 for", $b64_encode);
debug_output("Step 6 - R4 Applied", $r4_again);

echo("\n[+] At this point, we have extracted characters beyond the first four.")

/*
Output:
    [Step 1 - Initial Formatted String]: abcdefghij==
    [Step 2.1 - Quoted-Printable Encode 1]: abcdefghij=3D=3D
    [Step 2.2 - Quoted-Printable Encode 2]: abcdefghij=3D3D=3D3D
    [Step 2.3 - UTF-7 Encode 1]: abcdefghij+AD0-3D3D+AD0-3D3D
    [Step 2.4 - UTF-7 Encode 2]: abcdefghij+-AD0-3D3D+-AD0-3D3D
    [Step 2.5 - UTF-7 Encode 3]: abcdefghij+--AD0-3D3D+--AD0-3D3D
    [Step 2.6 - UTF-7 Encode 4]: abcdefghij+---AD0-3D3D+---AD0-3D3D
    [Step 3 - R2 should append <0xff><0xfe> (fffe in hex) for]: abcdefghij+---AD0-3D3D+---AD0-3D3D
    [Step 3 - The HEX Pre-R2 input (Before applying CSUNICODE)]: 6162636465666768696a2b2d2d2d4144302d334433442b2d2d2d4144302d33443344
    [Step 3 - CSUNICODE applied (expect <0xff><0xfe>)]: fffe6162636465666768696a2b2d2d2d4144302d334433442b2d2d2d4144302d33443344
    [Step 3 - CSUNICODE applied (Formatted Byte Output)]: \xff\xfeabcdefghij+---AD0-3D3D+---AD0-3D3D
    [Step 4 - R4 should swap chunks of 4 for]: \xff\xfeabcdefghij+---AD0-3D3D+---AD0-3D3D
    [Step 4 - The HEX Pre-R4 input (Before applying UCS-4LE.10646-1:1993)]: abcdefghij+---AD0-3D3D+---AD0-3D3D
    [Step 4 - R4 Applied]: 6261feff666564636a6968672d2d2d2b2d304441443344332d2d2d2b2d30444144334433
    [Step 4 - 10646-1:1993 Applied (Formatted Byte Output)]: ba\xfe\xfffedcjihg---+-0DAD3D3---+-0DAD3D3
    [Step 5 - Base64 Decode+Encode to recover string format]: bafedcjihg+0DAD3D3+0DAD3Dw==
    [Step 6 - R4 should swap chunks of 4 for]: bafedcjihg+0DAD3D3+0DAD3Dw==
    [Step 6 - R4 Applied]: efabijcd0+gh3DAD0+3D3DAD==wD

    [+] At this point, we have extracted characters beyond the first four.
 */
?>


