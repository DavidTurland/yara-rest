rule Example_One
{
    meta:
        my_identifier_1 = "Some string data"
    strings:
        $string1 = "pay"
        $string2 = "immediately"

    condition:
        ($string1 and $string2)
}
