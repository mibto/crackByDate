package ch.zhaw.sws2.random.encryptbydate;

import ch.zhaw.sws2.random.bydate.ByDate;
import org.junit.Test;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;


public class ByDateTest
{
    @Test
    public void encryptTest()
        throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, InvalidKeyException, InvalidParameterSpecException
    {
        String[] args = new String[6];
        args[0] = "encrypt";
        args[1] = "AES/CTR/NoPadding";
        args[2] = "2016-03-31T11:44:30+02:00";
        args[3] = "10000";
        args[4] = "/home/mib/Downloads/material/original";
        args[5] = "/home/mib/Downloads/material/encrypted";
        ByDate.main( args );
    }

    @Test
    public void decryptTest()
        throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IOException, InvalidKeyException, InvalidParameterSpecException
    {
        String[] args = new String[6];
        args[0] = "decrypt";
        args[1] = "AES/CTR/NoPadding";
        args[2] = "2016-03-31T11:44:30+02:00";
        args[3] = "10000";
        args[5] = "/home/mib/Downloads/material/decrypted";
        args[4] = "/home/mib/Downloads/material/encrypted";
        ByDate.main( args );
    }
}
