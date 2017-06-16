package com.hackathon.vz;
import java.util.ArrayList;
import java.util.List;

import com.amazonaws.auth.BasicAWSCredentials;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3Client;
import com.amazonaws.services.sns.AmazonSNSClient;
import com.amazonaws.services.sns.model.PublishRequest;
import com.amazonaws.services.sns.model.PublishResult;
import com.amazonaws.services.s3.model.*; //S3Object;
import com.amazonaws.services.ec2.AmazonEC2Client;
import com.amazonaws.services.ec2.model.DescribeSecurityGroupsRequest;
import com.amazonaws.services.ec2.model.DescribeVolumesResult;
import com.amazonaws.services.ec2.model.IpPermission;
import com.amazonaws.services.ec2.model.SecurityGroup;
import com.amazonaws.services.ec2.model.Volume;
import com.amazonaws.services.rds.AmazonRDS;
import com.amazonaws.services.rds.AmazonRDSClient;
import com.amazonaws.services.rds.model.DBInstance;
import com.amazonaws.services.rds.model.DescribeDBInstancesRequest;




public class SecurityMonitor {
	
	public static ListObjectsRequest req;
	static BasicAWSCredentials awscred= new BasicAWSCredentials("AKIAI4K53BR3RJXZEYOQ","oTm3VQJJRe2KKJoaSMARdrT0gWvcJoeNlT1zXH2C");
	
	public static void main(String args[]){
					
		System.out.println("Start");
		ArrayList<String> rds   = checkRDSEncryption();
		ArrayList<String> s3    = checkS3Encryption();
		ArrayList<String> s3ACL = checkS3ACL();
		ArrayList<String> ebs   = checkEBSEncryption();
		
		ArrayList<String> sg    = checkSGEncryption();
		
		if (!rds.isEmpty() || !s3.isEmpty() || !s3ACL.isEmpty() || !ebs.isEmpty() || !sg.isEmpty()){
		
			AmazonSNSClient snsClient = new AmazonSNSClient(awscred);
			String topicArn = "arn:aws:sns:us-east-1:818248616289:S3Notice";
			String msg = "Below are the services with out encryption \n\n";
			
			
			if(!rds.isEmpty()){
				msg=msg+"RDS instances: \n";
				for(String s:rds){
					msg=msg+s+","; 	
				}
				msg=msg+"\n\n";
			}
			if(!s3.isEmpty()){
				msg=msg+"S3 Buckets: \n";
				for(String s:s3){
					msg=msg+s+","; 	
				}
				msg=msg+"\n\n";
			}
			if(!s3ACL.isEmpty()){
				msg=msg+"S3 Buckets with global ACL: \n";
				for(String s:s3ACL){
					msg=msg+s+","; 	
				}
				msg=msg+"\n\n";
			}
			if(!ebs.isEmpty()){
				msg=msg+"EBS Volumes: \n";
				for(String s:ebs){
					msg=msg+s+","; 	
				}
				msg=msg+"\n\n";
			}
			if(!sg.isEmpty()){
				msg=msg+"Security Groups other than TCP 80: \n";
				for(String s:sg){
					msg=msg+s+","; 	
				}
				msg=msg+"\n\n";
			}
			
			msg=msg+"\n"+"This is auto generated mail. Do not Reply. \n\n Regards,\n Vision Visionaries";
			
			PublishRequest publishRequest = new PublishRequest(topicArn, msg);
			publishRequest.setSubject("Alert:List of services not having encryption in AWS - AWS Hackathon");
			PublishResult publishResult = snsClient.publish(publishRequest);
			System.out.println(msg);
			System.out.println("MessageId - " + publishResult.getMessageId());
		}
		
	}	

//check for S3 bucket Encryption
	public static ArrayList checkS3Encryption(){
		AmazonS3 s3Client = new AmazonS3Client(awscred);
		ArrayList<String> out = new ArrayList<String>();
		List<Bucket> object = (List<Bucket>)s3Client.listBuckets();
				
		List<S3ObjectSummary> obj;
		
		
		for(Bucket bk:object){
				
			ObjectListing ol =s3Client.listObjects(bk.getName());
		
			obj=ol.getObjectSummaries();
			if (!obj.isEmpty()){
				int count=0;
				for (S3ObjectSummary i:obj){
					String keyName = i.getKey();
					GetObjectMetadataRequest request2 = 
							new GetObjectMetadataRequest(bk.getName(),keyName);
					ObjectMetadata metadata = s3Client.getObjectMetadata(request2);
					
					if (metadata.getServerSideEncryption()==null){
					 	count++;
					 }
				}
				if(count>0){
					out.add(bk.getName());
				}
			}
		
		}	
		return out;
	}
	public static ArrayList checkS3ACL(){
		AmazonS3 s3Client = new AmazonS3Client(awscred);
		ArrayList<String> out = new ArrayList<String>();
		List<Bucket> object = (List<Bucket>)s3Client.listBuckets();
		for(Bucket bk:object){
			AccessControlList bucketAcl = s3Client.getBucketAcl(bk.getName());
			
			List<Grant> grantList=bucketAcl.getGrantsAsList();
			int count=0;
			for (Grant g:grantList){
				//Permission perm=grantList.get(0).getPermission();
				if(g.getGrantee().toString().contains("AllUsers")){
					count++;
					
				}
				
				
			}
			if (count>0){
				out.add(bk.getName());
			}
		}
		return out;
		
	}
	public static ArrayList checkEBSEncryption(){
		AmazonEC2Client ec2Client = new AmazonEC2Client(awscred);
		ArrayList<String> out = new ArrayList<String>();
		
		DescribeVolumesResult result= ec2Client.describeVolumes();
		List<Volume> list= result.getVolumes();
		
		for (Volume v:list)
		{
			
			if(!v.isEncrypted()){
				out.add(v.getVolumeId());
				
			}
		}
		return out;
	}
	
	public static ArrayList<String> checkSGEncryption(){
		AmazonEC2Client ec2Client = new AmazonEC2Client(awscred);
		ArrayList<String> out = new ArrayList<String>();
		List<SecurityGroup> sg=ec2Client.describeSecurityGroups(new DescribeSecurityGroupsRequest()).getSecurityGroups();
		
		int port, count=0,flag;
		String protocol;
		for (SecurityGroup secg:sg){
			
			count=0;
			flag=0;
			List<IpPermission> perm=secg.getIpPermissions();
			
			for (IpPermission i:perm){
								
				if (!i.getIpProtocol().equals("-1")){
					protocol=i.getIpProtocol();
					port=i.getFromPort();
					System.out.println("in if");
					if (protocol.equalsIgnoreCase("tcp") && port!=80){
						count++;
					}
				}else{
					flag=1;
					System.out.println("in else");
					break;
				}
			}
			if (count >1 || flag==1){
				out.add(secg.getGroupId());
			}
		}
		//System.out.println(vol.get(0));
		return out;
		
	}
	public static ArrayList checkRDSEncryption(){
		AmazonRDS client = new AmazonRDSClient(awscred);
		ArrayList<String> out = new ArrayList<String>();
		List<DBInstance> rds=client.describeDBInstances(new DescribeDBInstancesRequest()).getDBInstances();

		boolean isDbEncrypted=true;
			
		
		for (DBInstance i:rds)
		{
			
			isDbEncrypted = i.isStorageEncrypted();
								
			if (isDbEncrypted == false)
			{
				out.add(i.getDBInstanceIdentifier());
			}	
		}
		return out;
	}
}
