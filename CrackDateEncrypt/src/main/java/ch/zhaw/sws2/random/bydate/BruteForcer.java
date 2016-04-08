package ch.zhaw.sws2.random.bydate;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidParameterSpecException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.DoubleAccumulator;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * <p>BruteForcer to brute force the "Netscape encryption".
 * Multiple BruteForcers can be used and run in parallel to
 * search different parts of the keyspace at the same time.
 * Bruteforcing stops when the assigned keyspace has been
 * searched or when one of the BruteForcers finds a candidate
 * that is considered "good enough" based on the rating of the
 * candidate and a threshold for the rating.</p>
 * <p>
 * <p>It keeps track of promising candidates</p>
 *
 * @author Bernhard Tellenbach &lt;tebe@zhaw.ch&gt;
 * @version 1.0
 * @date 2016-03-06
 */
public class BruteForcer
{
    private static final double             LN2              = Math.log( 2.0 );
    private static       AtomicBoolean      isContinueSearch = new AtomicBoolean( true );
    private              TreeSet<Candidate> set              = new TreeSet<>( Comparator.comparingDouble( Candidate::getRating ) );
    private              byte[]             decryptedContent = new byte[ Crack.DECRYPT_MAX_BYTES ];

    private static final double RATING_THRESHOLD_TO_STOP_SEARCHING = 1;

    private MyFakeSystemImpl system;
    private NetscapeKeygen   keygen;
    private String           cipherSpec;
    private double           currentMinRating;
    private String           cipherAlgorithm;

    public BruteForcer( String cipherSpec, long uSeconds, ZonedDateTime date )
    {
        System.out.println(uSeconds);
        this.system = new MyFakeSystemImpl( uSeconds, date.getZone() );
        this.cipherSpec = cipherSpec;
        this.cipherAlgorithm = getCipherAlgorithmFromSpec( cipherSpec );

    }

    private static String getCipherAlgorithmFromSpec( String cipherSpec )
    {
        return cipherSpec.split( "/" )[ 0 ];
    }

    public Candidate getBestCandidate()
    {
        return set.first();
    }

    public void run( byte[] encryptedData )
    {
        System.out.println( "running" );
       // for(long i = 0; i < 660; i = i + 30) {
            long usecOffset = 0;
        system.addMicroseconds( 19*30*Constants.SECONDS_PER_MINUTE*Constants.USECS_PER_SECOND );
        //    system.addMicroseconds( i * Constants.SECONDS_PER_MINUTE * Constants.USECS_PER_SECOND);
            while ( usecOffset < Constants.USECS_PER_SECOND ) {
                try {
                    keygen = new NetscapeKeygen( system, cipherAlgorithm );
                    decrypt( encryptedData );
                    double rating = getRating();
                    //System.out.println(rating);
                    if ( rating < 7.5 ) {
                        System.out.println( new String( decryptedContent ) );
                        System.out.println( getRating() );
                    }
                    system.addMicroseconds( 1 );
                    usecOffset++;
                } catch ( Exception e ) {
                    e.printStackTrace();
                }
            }
      //  }
    }

    private boolean updateRating( boolean continueSearch )
    {
        double rating = getRating();
        if ( rating < currentMinRating ) {
            currentMinRating = rating;

            set.add( new Candidate( system, decryptedContent, rating ) );
            if ( rating < RATING_THRESHOLD_TO_STOP_SEARCHING ) {
                continueSearch = false;
                isContinueSearch.set( false );
            }
        }
        return continueSearch;
    }

    /**
     * Calculates a metric representing how "likely"
     * the "decrypted" data is indeed the plaintext
     *
     * @return rating
     */
    private double getRating()
    {
        Map<Character, Integer> map = new HashMap<>();
        // count the occurrences of each value
        for ( byte sequence : decryptedContent ) {
            Character character = new Character( (char)(sequence & 0xFF) );
            if ( !map.containsKey( character ) ) {
                map.put( character, 0 );
            }
            map.put( character, map.get( character ) + 1 );
        }

        // calculate the entropy
        Double result = 0.0;
        for ( Character sequence : map.keySet() ) {
            Double frequency = (double)map.get( sequence ) / decryptedContent.length;
            result -= frequency * (Math.log( frequency ) / Math.log( 2 ));
        }
        return result;
    }

    private void decrypt( byte[] encryptedData )
        throws BadPaddingException
    {
        Cipher cipher;
        try {
            keygen.makeKey();
            cipher = Cipher.getInstance( cipherSpec );
            AlgorithmParameters algParam = keygen.getAlgorithmParameters();
            algParam.init( new IvParameterSpec( keygen.getIv() ) );

            SecretKeySpec skeySpec = keygen.getSecretKeySpec();
            cipher.init( Cipher.DECRYPT_MODE, skeySpec, algParam );

            cipher.update( encryptedData, 0, encryptedData.length, decryptedContent, 0 );

        } catch ( NoSuchAlgorithmException
            | NoSuchPaddingException | InvalidParameterSpecException
            | InvalidKeyException
            | InvalidAlgorithmParameterException | ShortBufferException e ) {
            throw new IllegalStateException( e );
        }
    }
}