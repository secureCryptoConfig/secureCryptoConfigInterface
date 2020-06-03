package main;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;



public class JSONReader {
	
    //JSON parser object to parse read file
	static JSONParser jsonParser = new JSONParser();
	
	public enum CryptoUseCase            
	{
	   SymmetricEncryption, Signing, Hashing, AsymmetricEncryption ;  
	}
	
	public static ArrayList<String> getAlgos(CryptoUseCase useCase) 
    {
        ArrayList<String> algos = new ArrayList<String>();
        try (FileReader reader = new FileReader(".\\src\\main\\scc_example.json"))
        {
            //Read JSON file
            Object obj = jsonParser.parse(reader);
 
            JSONArray sccList = (JSONArray) obj;
            System.out.println(sccList);
            
            JSONObject scc = (JSONObject) sccList.get(0);
            
            
            JSONObject usageObject = (JSONObject) scc.get("Usage");
            JSONArray use = (JSONArray)usageObject.get(useCase.toString());
            Iterator iterator = use.iterator();
            while (iterator.hasNext()) {
               //System.out.println(iterator.next());
               algos.add((String)iterator.next());
            }
            return algos;
        } catch (IOException | ParseException e) {
            e.printStackTrace();
            return null;
        }
 
    }
	
	private static void getPublisher(JSONObject publisher) 
    {
      
        //Get publisher name
        String name = (String) publisher.get("name");    
        System.out.println(name);
        
        String url = (String) publisher.get("URL");    
        System.out.println(url);
 
    }
	
	private static void getUsage(CryptoUseCase useCase, JSONObject usageObject) 
    {
		System.out.println(useCase.toString());
		 JSONArray use = (JSONArray)usageObject.get(useCase.toString());
         Iterator iterator = use.iterator();
         while (iterator.hasNext()) {
            System.out.println(iterator.next());
         }
      
    }
	
	
	@SuppressWarnings("unchecked")
	public static void readJSON() {

         
        try (FileReader reader = new FileReader(".\\src\\main\\scc_example.json"))
        {
            //Read JSON file
            Object obj = jsonParser.parse(reader);
 
            JSONArray sccList = (JSONArray) obj;
            System.out.println(sccList);
            
            JSONObject scc = (JSONObject) sccList.get(0);
            
            String policyName = (String) scc.get("PolicyName");
            System.out.println(policyName);
            
            JSONArray publisherObject = (JSONArray) scc.get("Publisher");
            publisherObject.forEach( publisher -> getPublisher( (JSONObject) publisher ) );
            
            String version = (String) scc.get("Version");
            System.out.println(version);
            
            String policyIssueDate = (String) scc.get("PolicyIssueDate");
            System.out.println(policyIssueDate);
            
            String expiry = (String) scc.get("Expiry");
            System.out.println(expiry);
            
            JSONObject usageObject = (JSONObject) scc.get("Usage");
            Arrays.asList(CryptoUseCase.values()).
            forEach(useCase -> getUsage(useCase, usageObject));
 
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (ParseException e) {
            e.printStackTrace();
        }
   }
		
	public static void main(String[] args) {
		getAlgos(CryptoUseCase.SymmetricEncryption);
	}
	}

