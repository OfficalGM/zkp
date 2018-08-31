package zero_knowledge_proof;

import java.math.BigInteger;

public class NewClass {

    public static void main(String args[]) {
        Zero_Knowledge_proof zkp = new Zero_Knowledge_proof();
        BigInteger x = new BigInteger("5");
        BigInteger y = zkp.Prover_Commit();
//        System.out.println("y:"+y);
        BigInteger c = zkp.Verifier_Challenge();
//        System.out.println("c:"+c);
        BigInteger h = zkp.g.modPow(new BigInteger("3"), zkp.p);
//        System.out.println("h:"+h);
        BigInteger s = zkp.Prover_Compute(x, c);
//        System.out.println("s:"+s);
        System.out.println(zkp.Verifier(s, h, y, c));
    }
}
