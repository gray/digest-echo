use strict;
use warnings;
use Test::More tests => 19;
use Digest::ECHO qw(echo_384 echo_384_hex);

my $len = 0;

while (my $line = <DATA>) {
    chomp $line;
    my ($msg, $digest) = split '\|', $line, 2;
    my $data = pack 'H*', $msg;
    $digest = lc $digest;

    if ($len and not $len % 8) {
        my $md = Digest::ECHO->new(384)->add($data)->hexdigest;
        is($md, $digest, "new/add/hexdigest: $len bits of $msg");
        is(
            echo_384_hex($data), $digest,
            "echo_384_hex: $len bits of $msg"
        );
        ok(
            echo_384($data) eq pack('H*', $digest),
            "echo_384: $len bits of $msg"
        );
    }
    else {
        TODO:
        eval {
            local $TODO = 'add_bits is not yet implemented';
            my $md = Digest::ECHO->new(384)->add_bits($data, $len)
                ->hexdigest;
            is($md, $digest, "new/add_bits/hexdigest: $msg");
        };
    }
}
continue { $len++ }

__DATA__
00|134040763F840559B84B7A1AE5D6D64FC3659821A789CC64A7F1444C09EE7F81A54D72BEEE8273BAE5EF18EC43AA5F34
00|501ED1F97A8D6809605FCF108384E427331FB8781728425D06002AD9629A02400DC52354B785BB9958F08E0666FC89A3
C0|4141A2E11020774EAC81E8204490663DD5A4E36D1C8DA29298DD53F388BE275005A7ECC2BE3089B82548B082FC4533A8
C0|DA315E38BFD8311E817D38D4BB7847936DDF17D4EA2596B7DD8620F641666D09925417BF2EB4F092423E9B5A8472DAC3
80|62CE511A58BC39288E801B88D6473586DE55E50DF187C90A9F1E36078FE550621A158B89D73A10F0BF52858FD1C5BD7C
48|533B08F4EFD1ABDE7AECA245E9F218E664ED789CAA38AC7F779D48C3C09F0EF623DC699CE14D0C231C0453490355C5B2
50|B5622AE113D8D0CE669D231D5DB2A4852B20098AEF6C5493292483360D1C04F4474595C377CF55D01725BCCD19B95FA8
98|6F588C8D66EE10930A7F727A72AE3692AFA68A7425978726EB5E8F7122488143F801A563D2451F678C70FB49425F2906
CC|90875A2649CAB90018FF8AECD334482C92B15D76B378574EEAACD3B7598020DB11E2C7480614EEA8793DE3DAF2093F73
9800|34C33AD64AD9E5B318EA77A55DC0FE536C40F7F3F76005481A8FCF01E4BAA8C1D4A0F79A2B4A6F30BEBB2CC660F36FB1
9D40|87A51E67ABEECDD8033EC7BAF882341895364D5D911CB9FF0589171A492627C4911970B8BA7BFC0C85E238FD88869091
AA80|A7CB4799DDEB937BBC367C29208665A53BDE24E8A6EA66F8F0704AF816BBDA95EF9F47B4245513CB837F537BE24B6013
9830|E1158181F2163C65EF4B080F4092D6ED086AD5AEF48D53262656DC55ECE7BC142D947500D7188807F56F369C52217862
5030|986FCBEEB5DDB45F3D89B97FB0712D3B47E209BFC714CBDEA7EAA240A50519B86F73F31726A29EDD420A6AAE88A23649
4D24|EEC07EAF696C61652A919A92597F88A53508F961DDC1A7414E48A0A46796FF5A4A23CF41BB2F220DD52D7D24F7B77087
CBDE|86EEFDD2FC77BB9C437C4194D8CB6B763A968E6BFD5C011FCAABAF707D768A94EDF30A453A29C79E8C77081656ADD8AB
41FB|AD5618D59063A3E997B8A7309D8D198E41EFEEEA9AE42423F3DE2D2CD6135D991A86CD787D943C5FD4D89E03ABC67EF6
4FF400|AF102EF3166CDC37D455B2BFD6F2D2A55768602B4EF6AED8AAB77ABF8F02FF89728C661E992A7E8CE951626338B829A7
FD0440|3154942BF129ED2A4AF22FB5D485CD6E233DD794273B9D0F162319A31FDB4C7DB36E948C400AEC9837B5243AF420FB5D
424D00|EB79ABE0B39ADE953C1347678F0F338CD00E0B69725947751C096CAC551D47144189902C24E5EDB081BF2EAE0882B995
3FDEE0|6F780C395E81BFA3EC667938F5D7EFAA936FF8169A4D35E170D16EB76BCC8136F316FEFFE46FDEF1A4FEAB8F3B89CC0E
335768|18D15E4897EE2A8144B91819E5785EB64D7E70D02AC54D36BC1F1A0A4523ABB04ED20F69ACDA6214466395251EA05895
051E7C|6649F8F516E70B208273781F1A62D95EBFA722365E43C0EEE1FBA73C24DEE7D7D3F762C1409A9FF258C8586FE088886C
717F8C|0D144313840480EBA3A469CDED49470352AC54DD2E4436071D314DE8E045D49E63213BC2B6981A42FA14108BE210728F
1F877C|91F2A4A29CFEE555751C388AFB63317842E3EF02D7B02FB35ACF3F1CC18366BD37F2B0AEF1F329CF9658E03CCD8FB6C6
EB35CF80|A05073FC6012F090D0FACAE6EF33E894570B7F191D2D663F045FDD683AD479DC50CA46346F93374EE88AAFA90F05C5C1
B406C480|9ED94E1DA4C78B1CF795548F77ED7159FBDA1D723D4B9FD364C2E7309705598E08CAF6F924DD289DED8FEF83A6B57A85
CEE88040|16FD928FB5A01872D173EE72FE26D3C8043EA9AF0B47B4684CB8D955E79D42657FA5AA9B51E841A2304942BFA3D8B8E8
C584DB70|CC28079FC67D3F20783C769E776B1B6039A21064C618D039726C3DA0A74DF0A4B9AE203D7240094BCA9CC9194E6E8473
53587BC8|C362AE9328504CBA0C4BC30C7989942C746C1F9F3CA3F4C97437545C6AA65275FF807C3F97C0D035FDACC22BB6CD25A6
69A305B0|0C888DB8E2B28698E683FBE23BF91303B7696AC69DC1394376F4D2A4B1C23E35887C407E500DA385A6E0BD458797698C
C9375ECE|86AD4D6483F460FBA6D7FA12DE104942C98D7A50074CE2B443403E36C8A7862F1C6F2CFB1B2AC2391668478552F92D35
C1ECFDFC|78C0B40362CA51A76C89C0AF7DDDF4EBE0F6FE734F687FFD6A2110AC61CEA0D3B6BCB88AD624ECF148CEBEF89D330B57
8D73E8A280|A922A884FAAF37B0FBB81DB3A00EB66C85B86C957BA5264526E282B7EC035A667D88B611CBA33F7A94B7A5A0C0A2D1FE
06F2522080|DCC28F17F60F66C622F6CF11EB1A76531FA7415182ED03AD15CE232B1568FCBACE9B716BECD5DF4BD71CAFC70BFCFA2E
3EF6C36F20|6721633577CE5B30D77957F2EC98ACC3A9BD18189F29B43C90A7F1ED8389E6E98E9D232AC372239F38E9F88E5101F25E
0127A1D340|9AF63D124A88FA3A1F411F63E2CFA6A0B7508BA07D791C44D2C6B551382F94CE5CC970656E377FC639C152FFE781E7B5
6A6AB6C210|E1592E652EE371BBEC510706F978ED2659F51767FE40976F8BC6009EFF53B188A30D0991CEA7B0AF0363DB55D5C1C46A
AF3175E160|85C9467EF63AA82277A45B782D7DFE0F7CB37BF79DA3B7DA2BE411791B471E33A31E7798A007D803E0412DD18E29C14F
B66609ED86|79F7BF576ECF997AA092D9C2477188B55CDB328B9A0ADD479887E0A59309223A81EE083E034AE3A028EF68A1C4B63156
21F134AC57|DBE6A3938434AA072D686249810BD27D9BBF92469F0316DDA386367589EE09374D4FDCD4F72BCE19DF11448AF3F4F5DF
3DC2AADFFC80|E4BFAA6BCADBE9A8217735484D3A03CE09282E3960A9DE20F57CFF97138590C6F901FB037D29729BBD1AE2165A8C1492
9202736D2240|AC33117579081B8A7BE30B4B259EC3B810268CDB235F4DF4C83C54AECC033F72DAB7715AF3B1EAD1FAE5AABE085D73F9
F219BD629820|FDB9C6D7D1EBA526400A4BE57B75CD49B8651A2B11C7955C8A6FB8F235F93CEF5EA99572F468FD45990FA2D7A7C599EF
F3511EE2C4B0|4639C8F7142840287AA3783016156A14C3D2AD06B82C8A8C8452CB7F830B443D36D4A8D9D18046AA6520E9095C9B68CB
3ECAB6BF7720|9519AA7429836DC2B32BCEF6A6C62EBC88F43B0C23450179CD6AB84857AD636EE2DD8F065B61E11062F491C4B504E806
CD62F688F498|2BB14D20124146CA930E82C0E97D2F8BB343666602B23CA9F93CD6045553D48EFC525FB56CDB2D0DDA1F5F54F2BA6FF4
C2CBAA33A9F8|FFF3253CD0C14A4B3D3CBAA30A61E0CC12A66159C2B28595E53B4F274D3B7527A83F6B1FB37DCD132A2A52E7C5D76F51
C6F50BB74E29|FA2F0BAFD4AB905C686D99024B8A8C787CF2B5DC73F692FC41F866A5E5669D72A8D78955ECDAB670DB98229FC10A4480
79F1B4CCC62A00|2F5A9B02CF6F08FB9D4BE5301EA837CE4834624827D33F4F11C38AEE458B4AEAFA82E94296CD129A9E0A6312D0831F68
