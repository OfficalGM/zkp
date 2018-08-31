package zero_knowledge_proof;

import java.math.BigInteger;
import java.security.SecureRandom;

public class Zero_Knowledge_proof {

    public BigInteger g;
    private BigInteger t;
    public BigInteger p;
    private BigInteger order;
    private BigInteger TWO = new BigInteger("2");

    public Zero_Knowledge_proof() {
        init(7);
//        System.out.println("g:" + g);
//        System.out.println("p:" + p);

    }

    private void init(int nb_bits) {
        order = new BigInteger(nb_bits, 10, new SecureRandom());
        p = order.multiply(TWO).add(BigInteger.ONE);
        while (!p.isProbablePrime(10)) {
            order = new BigInteger(nb_bits, 10, new SecureRandom());
            p = order.multiply(TWO).add(BigInteger.ONE);
        }

        g = random_number(p);
        
        while (!g.modPow(order, p).equals(BigInteger.ONE)) {
            if (g.modPow(order.multiply(TWO), p).equals(BigInteger.ONE)) {
                g = g.modPow(TWO, p);
            } else {
                g = random_number(p);
            }
        }
    }

    public BigInteger Prover_Commit() {
        t = random_number(order);
        if (t.equals(BigInteger.ZERO)) {
            Prover_Commit();
        }
//        System.out.println("t:" + t);
        BigInteger y = g.modPow(t, p);//g^t mod p
        return y;
    }

    public BigInteger Verifier_Challenge() {
        BigInteger c = random_number(order);
        if (c.equals(BigInteger.ZERO)) {
            Verifier_Challenge();
        }
        return c;
    }

    public BigInteger Prover_Compute(BigInteger x, BigInteger c) {
        BigInteger temp = x.multiply(c).mod(order); //c*x mod p
        BigInteger s = t.add(temp).mod(order); // t+cx mod p
        return s;
    }

    public Boolean Verifier(BigInteger s, BigInteger h, BigInteger y, BigInteger c) {
        BigInteger temp = g.modPow(s, p);
        h = h.modPow(c, p);
        BigInteger temp2 = y.multiply(h).mod(p);
//        System.out.println("temp " + temp);
//        System.out.println("temp2 " + temp2);
        return temp.equals(temp2);//g^s mod p == y*h^c mod p
    }

    private BigInteger random_number(BigInteger n) {
        return new BigInteger(n.bitLength(), new SecureRandom()).mod(n);
    }
}
