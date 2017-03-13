import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class CryptoAnalysis {
	static String  alphabets="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	static String cipherTextForCeaserCipher="LT HDGJWJFLQJX";
	static String cipherTextForVignereCipher="UPRCW IHSGY OXQJR IMXTW AXVEB DREGJ AFNIS EECAG SSBZR" +
			"TVEZU RJCXT OGPCY OOACS EDBGF ZIFUB KVMZU FXCAD CAXGS"+
			"FVNKM SGOCG FIOWN KSXTS ZNVIZ HUVME DSEZU LFMBL PIXWR"+
			"MSPUS FJCCA IRMSR FINCZ CXSNI BXAHE LGXZC BESFG HLFIV ESYWO"+
			"RPGBD SXUAR JUSAR GYWRS GSRZP MDNIH WAPRK HIDHU ZBKEQ"+
			"NETEX ZGFUI FVRI";
	
	/* Main funcation, Entry Point */
	public static void main(String[] args){
		caeserCipher(cipherTextForCeaserCipher);
		vignereCipher(cipherTextForVignereCipher);
	}
	
	/* Calls all other functions to carry out Vignere Cyrptoanalysis */
	public static void vignereCipher(String cipherTextForVignereCipher){
		System.out.println("\n=============2. Vignere Cipher Analysis======================");
		System.out.println("\nVignere Cipher Text: "+cipherTextForVignereCipher);
		HashMap<Character,Double> freqOfCharsMap=calculateFrequencyOfCharacters(cipherTextForVignereCipher);
		System.out.println("\nFrequency of alphabets: "+ freqOfCharsMap);
		double iCValue=calculateIndexOfCoincidence(freqOfCharsMap);
		System.out.println("\nIndex Of Coincidence: "+ iCValue);
		int keyLength=calculateKeyLength(iCValue);
		System.out.println("\nKey Length: "+ keyLength);
		System.out.println("\nNumber of Buckets:"+ keyLength);
		HashMap<Integer,String> bucket= putCipherTextInBucket(cipherTextForVignereCipher,keyLength);
		printBuckets(bucket);
		//System.out.println("\nBuckets: "+bucket);
		HashMap<Integer,HashMap<Integer,Double>> probableKeysPerBucket=getProbableKeysPerBucket(bucket);
		HashMap<Integer,HashMap<Integer, Double>> finalHashMap=getTopMostCorrelationValAndKey(probableKeysPerBucket);
		List<Integer> list=new ArrayList<Integer>();
		for (Map.Entry<Integer, HashMap<Integer, Double>> item : finalHashMap.entrySet()) {
			HashMap<Integer, Double> valueFromFinalHashMap=item.getValue();
			for (Map.Entry<Integer,Double> itemVal : valueFromFinalHashMap.entrySet()) {
				list.add(itemVal.getKey());
			}
		}
		printListOfKeys(list);
		getVignereDecipheredText(cipherTextForVignereCipher,list);
	}
	
	/* Prints list of keys for Each Bucket */
	public static void printListOfKeys(List<Integer> list){
		System.out.println("\n=========List of Bucket and their Keys:===========");
		System.out.println("Bucket\t\tKey Length");
		for(int i=0;i<list.size();i++){
			System.out.println(i+"\t\t"+list.get(i));
		}
	}
	/* Prints String bucket wise */
	public static void printBuckets(HashMap<Integer,String> bucket){
		System.out.println("");
		for (Map.Entry<Integer, String> item : bucket.entrySet()) {
			System.out.println("Bucket"+item.getKey()+"\t\t"+item.getValue());
		}
	}
	
	/* This function bucktetizes the given ciphertext with the given key lenth */
	public static HashMap<Integer,String>  putCipherTextInBucket(String cipherText, int keyLength){
		HashMap<Integer,String> bucket=new HashMap<Integer, String>();
		int cipherTextIndex=0;
		String cipher_text = cipherText.replace(" ","");
		while (cipherTextIndex<cipher_text.length()){
			Character characterVal=cipher_text.charAt(cipherTextIndex);
			String charAtATime=Character.toString(characterVal);
			
			 if (charAtATime != " "){
				int bucket_index = (cipherTextIndex % keyLength);
				String bucketText="";
				if(bucket.containsKey(bucket_index))
					bucketText=bucket.get(bucket_index);
				else
					bucketText="";
				bucketText = bucketText.concat(charAtATime);
				bucket.put(bucket_index, bucketText); 
			 }
			 cipherTextIndex = cipherTextIndex+1;
		}
		return bucket;
		}
	
	/* This function returns the probable keys per bucket */
	public static HashMap<Integer,HashMap<Integer,Double>> getProbableKeysPerBucket(HashMap<Integer,String> bucket){
			
			HashMap<Integer,HashMap<Integer,Double>> probable_keys=new HashMap<Integer,HashMap<Integer,Double>>();
			HashMap<Character,Double> freqOfCharsMap=calculateFrequencyOfCharacters(cipherTextForVignereCipher);

				for (Map.Entry<Integer, String> item : bucket.entrySet()) {
					freqOfCharsMap=calculateFrequencyOfCharacters(item.getValue());
					HashMap<Integer,Double> correlationFxn=corelationFunction(freqOfCharsMap,createXXChart());
					probable_keys.put(item.getKey(), correlationFxn);
				}
			return probable_keys;
		}
	
	/* Dechiphers the ciphered text and displays the result */
	public static void getVignereDecipheredText(String cipherText,List<Integer> bucketKeys){
		
		String plainText="";
		int index =0;
		for(int i = 0; i < cipherText.length(); i++){
			  char c = cipherText.charAt(i);
			   if(c == ' '){
				   plainText=plainText+" ";
				   }else{
					   int key=bucketKeys.get(index % bucketKeys.size());
					   plainText= plainText + Character.toString(alphabets.charAt((decipher(c,key))));
					   index=index+1;
				   } 
		}
		
		System.out.println("\nPlain Text with spaces: ");
		System.out.println(plainText);
		System.out.println("\nPlain Text without spaces: ");
		System.out.println(plainText.replace(" ", ""));
	}

	public static HashMap<Integer, HashMap<Integer, Double>> getTopMostCorrelationValAndKey(HashMap<Integer,HashMap<Integer,Double>> probableKeysPerBucket){
		int a=0;
		HashMap<Integer, Double> maxCorelationValForEachBucket=new HashMap<Integer, Double>();
		HashMap<Integer, HashMap<Integer, Double>> finalHashMap=new HashMap<Integer, HashMap<Integer, Double>>();

		for (Map.Entry<Integer, HashMap<Integer,Double>> itemBucket : probableKeysPerBucket.entrySet()) {
			maxCorelationValForEachBucket=sortByValue(itemBucket.getValue(),1);
			finalHashMap.put(a, maxCorelationValForEachBucket);
			a=a+1;
			
		}
		return finalHashMap;
	}
	
	/*Calculated Key Length from given Index Of Coincidence Value */
	public static int calculateKeyLength(double iCValue){
		double iC=0.0;
		int keyLength=0;
		if(iCValue>=0.052 && iCValue<0.066){
			iC=getCloserValue(0.052,0.066,iCValue);
			if(iC==066) keyLength=1;
			else keyLength=2;
		}
		else if(iCValue>=0.047 && iCValue<0.052){
			iC=getCloserValue(0.047,0.052,iCValue);
			if(iC==0.052) keyLength=2;
			else keyLength=3;
		}
		else if(iCValue>=0.045 && iCValue<0.047){
			iC=getCloserValue(0.045,0.047,iCValue);
			if(iC==0.047) keyLength=3;
			else keyLength=4;
		}
		else if(iCValue>=0.045 && iCValue<0.044){
			iC=getCloserValue(0.045,0.044,iCValue);
			if(iC==0.044) keyLength=4;
			else keyLength=5;
		}
		else if(iCValue==0.044){
			keyLength=5;
		}
		else if(iCValue>=0.0425 && iCValue<0.044){
			iC=getCloserValue(0.0425,0.044,iCValue);
			if(iC==0.044) keyLength=5;
			else keyLength=6;
		}
		else if(iCValue>=0.041 && iCValue<0.0425){
			iC=getCloserValue(0.041,0.0426,iCValue);
			if(iC==0.0425) keyLength=6;
			else keyLength=10;
		}
		else if (iCValue<0.41)
			System.out.println("Very small Index Of Coincidence gives very big Key Length");
		
		return keyLength;
		
	}

	public static double getCloserValue(double min_val,double max_val,double indexOfCoincidence){
		if(Math.abs(max_val-indexOfCoincidence)<Math.abs(min_val-indexOfCoincidence))
			return max_val;
		else
			return min_val;
	}
	
	/* Performs Ceaser Cipher Cryptanalysis */
	public static void caeserCipher(String cipherTextForCeaserCipher){
		HashMap<Character,Double> xxChartMap=createXXChart();
		HashMap<Character,Double> frequencyMap=calculateFrequencyOfCharacters(cipherTextForCeaserCipher);
		HashMap<Integer,Double> corelationValue=corelationFunction(frequencyMap,xxChartMap);
		int noOfSortedCorelationvalues=5;
		HashMap<Integer,Double> sortedCorelationValue=sortByValue(corelationValue,noOfSortedCorelationvalues);
		getPlaintext(sortedCorelationValue);	
	}
	
	/*Calcultaes the Index of coincidence */
	public static double calculateIndexOfCoincidence(HashMap<Character,Double> freqOfCharsMap){
		double sum=0;
		double count=0;
		for (Map.Entry<Character, Double> item : freqOfCharsMap.entrySet()) {
			count=count+item.getValue();
		}
		for (Map.Entry<Character, Double> item : freqOfCharsMap.entrySet()) {
			double temp1=item.getValue()*(item.getValue()-1);
			sum=sum+temp1;
		}
		double constant=(count*(count-1));
		return sum/constant;
		
	}

	/* Calculated frequency of Characters in a cipher text and stores in hashmap*/
	public static HashMap<Character,Double> calculateFrequencyOfCharacters(String cipherText){
		HashMap<Character,Double> map = new HashMap<Character,Double>();          
		for(int i = 0; i < cipherText.length(); i++){
		   char c = cipherText.charAt(i);
		   if(c != ' '){
			   Double val = map.get(new Character(c));
			   if(val != null){
			     map.put(c, new Double(val + 1));
			   }else{
			     map.put(c,1.0);
			   } 
		   }
		}
		return map;
	}
	
	/* Get Plain Text from Cipher Text using Ceaser Cipher*/
    private static void getPlaintext(HashMap<Integer,Double> sortedCorelationValue) {
    	System.out.println("=============1. Ceaser Cipher Analysis====================");
    	System.out.println("\nCipher Text: " +cipherTextForCeaserCipher+"\n");
    	System.out.println("Key"+"\t"+"Plain text");
		for (Map.Entry<Integer, Double> item : sortedCorelationValue.entrySet()) {
			String plaintext="";
			for(int j=0;j<cipherTextForCeaserCipher.length();j++){
				int index=decipher(cipherTextForCeaserCipher.charAt(j),item.getKey());
			if(cipherTextForCeaserCipher.charAt(j)== ' '){
					Character temp=' ';
					plaintext=plaintext+temp;
				}
				else{
					Character temp=' ';
					temp=alphabets.charAt(index);
					plaintext=plaintext+temp;
				}
			}
			System.out.println(item.getKey()+"\t "+plaintext);
		}
	System.out.println("Key: 5 \t Meaningful Plain Text: GO CYBEREAGLES");
	}

    /* Sorts hashmap on the basis of corelation values, returns noToSort descending list */
	private static HashMap<Integer, Double> sortByValue(HashMap<Integer, Double> unsortMap, int noToSort) {

        // 1. Convert Map to List of Map
        List<Map.Entry<Integer, Double>> list =
                new LinkedList<Map.Entry<Integer, Double>>(unsortMap.entrySet());

        // 2. Sort list with Collections.sort(), provide a custom Comparator
        //    Try switch the o1 o2 position for a different order
        Collections.sort(list, new Comparator<Map.Entry<Integer, Double>>() {
            public int compare(Map.Entry<Integer, Double> o1,
                               Map.Entry<Integer, Double> o2) {
                return (o2.getValue()).compareTo(o1.getValue());
            }
        });

        // 3. Loop the sorted list and put it into a new insertion order Map LinkedHashMap
        HashMap<Integer, Double> sortedMap = new LinkedHashMap<Integer, Double>();
        HashMap<Integer, Double> fiveSortedMap = new LinkedHashMap<Integer, Double>();
        int i=1;
        for (HashMap.Entry<Integer, Double> entry : list) {
            sortedMap.put(entry.getKey(), entry.getValue());
          if(i<=noToSort){
            	fiveSortedMap.put(entry.getKey(), entry.getValue());
            	i=i+1;
            }
        }
        return fiveSortedMap;
    }

	/* Calculates corelation values */
	public static HashMap<Integer,Double> corelationFunction(HashMap<Character,Double> frequencyMap,HashMap<Character,Double> xxChartMap ){
		int lengthOfUniqueAlphabets=frequencyMap.size();
		HashMap<Integer,Double> corelationValue=new HashMap<Integer,Double>();
		for(int i=0;i<26;i++){
			double sum=0;
			for (Map.Entry<Character, Double> item : frequencyMap.entrySet()) {
					  Character key = item.getKey();
					  Double value = item.getValue();
					  double fVal=value/lengthOfUniqueAlphabets;
					  int decipherIndex=decipher(key,i);
					  Character alpha=alphabets.charAt(decipherIndex);
					  double fPrime=xxChartMap.get(alpha);
					  double valAfterMult=fVal*fPrime;
					  sum=sum+valAfterMult;
			}
			corelationValue.put(i, sum);
		}
		return corelationValue;
	}
	
	/* Deciphers alphabets for given key */
	public static int decipher(Character k, int i){
		int e=alphabets.indexOf(k);
		int val=(26+e-i) % 26;
		return val;
		
	}
	
	/*Creates XX chart */
	public static HashMap<Character,Double> createXXChart(){
		
		Double[] frequencies={0.080, 0.015, 0.030,0.040, 0.130, 0.020, 0.015, 0.060, 0.065, 0.005, 0.005, 0.035, 0.030, 
							0.070, 0.080, 0.020, 0.002, 0.065,0.060, 0.090, 0.030, 0.010, 0.015, 0.005, 0.020, 0.002};
		
		HashMap<Character,Double> hm = new HashMap<Character,Double>();
		for(int i = 0; i < alphabets.length(); i++) {
		    hm.put(alphabets.charAt(i), frequencies[i]);	
		}
		return hm;
	}
	
}
