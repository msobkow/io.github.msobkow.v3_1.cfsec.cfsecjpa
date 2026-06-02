
// Description: Java 25 DbIO implementation for SecClusRole.

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsec.jpa;

import java.lang.reflect.*;
import java.net.*;
import java.rmi.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.EntityManager;
import jakarta.persistence.NoResultException;

import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.jpa.CFSecJpaHooksSchema;

/*
 *	CFSecJpaSecClusRoleTable database implementation for SecClusRole
 */
public class CFSecJpaSecClusRoleTable implements ICFSecSecClusRoleTable
{
	protected CFSecJpaSchema schema;


	public CFSecJpaSecClusRoleTable(ICFSecSchema schema) {
		if( schema == null ) {
			throw new CFLibNullArgumentException(getClass(), "constructor", 1, "schema" );
		}
		if (schema instanceof CFSecJpaSchema) {
			this.schema = (CFSecJpaSchema)schema;
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "constructor", "schema", schema, "CFSecJpaSchema");
		}
	}

	protected boolean canCreateSecClusRole(String S_ProcName, ICFSecAuthorization Authorization) {
		if (Authorization == null) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "Authorization");
		}
		boolean permissionGranted = false;
		CFLibDbKeyHash256 authUserId = Authorization.getSecUserId();
		if ((!permissionGranted) && (authUserId == null || authUserId.isNull())) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "Authorization.getSecUserId()");
		}
		// Check for "system" user
		CFLibDbKeyHash256 systemId = ICFSecSchema.getSystemId();
		if ((!permissionGranted) && (systemId != null && !systemId.isNull() && systemId.equals(authUserId))) {
			permissionGranted = true;
		}
		else if ((!permissionGranted) && (systemId == null || systemId.isNull())) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "ICFSecSchema.getSystemId()");
		}
		if(!permissionGranted) {
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfClusterGroup(Authorization.getSecUserId(), Authorization.getSecClusterId(), "createsecclusrole");
		}
		return( permissionGranted );
	}

	protected boolean canReadSecClusRole(String S_ProcName, ICFSecAuthorization Authorization) {
		if (Authorization == null) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "Authorization");
		}
		boolean permissionGranted = false;
		CFLibDbKeyHash256 authUserId = Authorization.getSecUserId();
		if ((!permissionGranted) && (authUserId == null || authUserId.isNull())) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "Authorization.getSecUserId()");
		}
		// Check for "system" user
		CFLibDbKeyHash256 systemId = ICFSecSchema.getSystemId();
		if ((!permissionGranted) && (systemId != null && !systemId.isNull() && systemId.equals(authUserId))) {
			permissionGranted = true;
		}
		else if ((!permissionGranted) && (systemId == null || systemId.isNull())) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "ICFSecSchema.getSystemId()");
		}
		if(!permissionGranted) {
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfClusterGroup(Authorization.getSecUserId(), Authorization.getSecClusterId(), "readsecclusrole");
		}
		return( permissionGranted );
	}

	protected boolean canUpdateSecClusRole(String S_ProcName, ICFSecAuthorization Authorization) {
		if (Authorization == null) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "Authorization");
		}
		boolean permissionGranted = false;
		CFLibDbKeyHash256 authUserId = Authorization.getSecUserId();
		if ((!permissionGranted) && (authUserId == null || authUserId.isNull())) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "Authorization.getSecUserId()");
		}
		// Check for "system" user
		CFLibDbKeyHash256 systemId = ICFSecSchema.getSystemId();
		if ((!permissionGranted) && (systemId != null && !systemId.isNull() && systemId.equals(authUserId))) {
			permissionGranted = true;
		}
		else if ((!permissionGranted) && (systemId == null || systemId.isNull())) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "ICFSecSchema.getSystemId()");
		}
		if(!permissionGranted) {
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfClusterGroup(Authorization.getSecUserId(), ICFSecSchema.getSysClusterId(), "updatesecclusrole");
		}
		return( permissionGranted );
	}

	protected boolean canDeleteSecClusRole(String S_ProcName, ICFSecAuthorization Authorization) {
		if (Authorization == null) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "Authorization");
		}
		boolean permissionGranted = false;
		CFLibDbKeyHash256 authUserId = Authorization.getSecUserId();
		if ((!permissionGranted) && (authUserId == null || authUserId.isNull())) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "Authorization.getSecUserId()");
		}
		// Check for "system" user
		CFLibDbKeyHash256 systemId = ICFSecSchema.getSystemId();
		if ((!permissionGranted) && (systemId != null && !systemId.isNull() && systemId.equals(authUserId))) {
			permissionGranted = true;
		}
		else if ((!permissionGranted) && (systemId == null || systemId.isNull())) {
			throw new CFLibNullArgumentException(getClass(), S_ProcName, 0, "ICFSecSchema.getSystemId()");
		}
		if(!permissionGranted) {
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfClusterGroup(Authorization.getSecUserId(), ICFSecSchema.getSysClusterId(), "deletesecclusrole");
		}
		return( permissionGranted );
	}

	/**
	 *	Create the instance in the database, and update the specified record
	 *	with the assigned primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	rec	The instance interface to be created.
	 */
	@Override
	public ICFSecSecClusRole createSecClusRole( ICFSecAuthorization Authorization,
		ICFSecSecClusRole rec )
	{
		final String S_ProcName = "createSecClusRole";
		boolean permissionGranted = canCreateSecClusRole(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "createsecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			throw new CFLibNullArgumentException(getClass(), "createSecClusRole", 1, "rec");
		}
		else if (rec instanceof CFSecJpaSecClusRole) {
			CFSecJpaSecClusRole jparec = (CFSecJpaSecClusRole)rec;
			jparec.setCreatedAt(LocalDateTime.now());
			jparec.setUpdatedAt(jparec.getCreatedAt());
			jparec.setCreatedByUserId(Authorization.getSecUserId());
			jparec.setUpdatedByUserId(Authorization.getSecUserId());
			CFSecJpaSecClusRole retval = schema.getJpaHooksSchema().getSecClusRoleService().create(jparec);
		return(retval);
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "createSecClusRole", "rec", rec, "CFSecJpaSecClusRole");
		}
	}

	/**
	 *	Update the instance in the database, and update the specified record
	 *	with any calculated changes imposed by the associated stored procedure.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	rec	The instance interface to be updated
	 */
	@Override
	public ICFSecSecClusRole updateSecClusRole( ICFSecAuthorization Authorization,
		ICFSecSecClusRole rec )
	{
		final String S_ProcName = "updateSecClusRole";
		boolean permissionGranted = canUpdateSecClusRole(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatesecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			throw new CFLibNullArgumentException(getClass(), "updateSecClusRole", 1, "rec");
		}
		else if (rec instanceof CFSecJpaSecClusRole) {
			CFSecJpaSecClusRole jparec = (CFSecJpaSecClusRole)rec;
			jparec.setUpdatedAt(LocalDateTime.now());
			jparec.setUpdatedByUserId(Authorization.getSecUserId());
			CFSecJpaSecClusRole retval = schema.getJpaHooksSchema().getSecClusRoleService().update(jparec);
		return(retval);
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "updateSecClusRole", "rec", rec, "CFSecJpaSecClusRole");
		}
	}

	/**
	 *	Delete the instance from the database.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	rec	The instance interface to be deleted.
	 */
	@Override
	public void deleteSecClusRole( ICFSecAuthorization Authorization,
		ICFSecSecClusRole rec )
	{
		final String S_ProcName = "deleteSecClusRole";
		boolean permissionGranted = canDeleteSecClusRole(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			return;
		}
		if (rec instanceof CFSecJpaSecClusRole) {
			CFSecJpaSecClusRole jparec = (CFSecJpaSecClusRole)rec;
			schema.getJpaHooksSchema().getSecClusRoleService().deleteByIdIdx(jparec.getPKey());
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "deleteSecClusRole", "rec", rec, "CFSecJpaSecClusRole");
		}

		throw new CFLibNotImplementedYetException(getClass(), "deleteSecClusRole");
	}

	/**
	 *	Delete the SecClusRole instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The primary key identifying the instance to be deleted.
	 */
	@Override
	public void deleteSecClusRoleByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argKey )
	{
		final String S_ProcName = "deleteSecClusRoleByIdIdx";
		boolean permissionGranted = canDeleteSecClusRole(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecClusRoleService().deleteByIdIdx(argKey);
	}

	/**
	 *	Delete the SecClusRole instances identified by the key ClusterIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ClusterId	The SecClusRole key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecClusRoleByClusterIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argClusterId )
	{
		final String S_ProcName = "deleteSecClusRoleByClusterIdx";
		boolean permissionGranted = canDeleteSecClusRole(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecClusRoleService().deleteByClusterIdx(argClusterId);
	}


	/**
	 *	Delete the SecClusRole instances identified by the key ClusterIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteSecClusRoleByClusterIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleByClusterIdxKey argKey )
	{
		final String S_ProcName = "deleteSecClusRoleByClusterIdx";
		boolean permissionGranted = canDeleteSecClusRole(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecClusRoleService().deleteByClusterIdx(argKey.getRequiredClusterId());
	}

	/**
	 *	Delete the SecClusRole instances identified by the key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	Name	The SecClusRole key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecClusRoleByNameIdx( ICFSecAuthorization Authorization,
		String argName )
	{
		final String S_ProcName = "deleteSecClusRoleByNameIdx";
		boolean permissionGranted = canDeleteSecClusRole(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecClusRoleService().deleteByNameIdx(argName);
	}


	/**
	 *	Delete the SecClusRole instances identified by the key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteSecClusRoleByNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleByNameIdxKey argKey )
	{
		final String S_ProcName = "deleteSecClusRoleByNameIdx";
		boolean permissionGranted = canDeleteSecClusRole(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecClusRoleService().deleteByNameIdx(argKey.getRequiredName());
	}

	/**
	 *	Delete the SecClusRole instances identified by the key UNameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ClusterId	The SecClusRole key attribute of the instance generating the id.
	 *
	 *	@param	Name	The SecClusRole key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecClusRoleByUNameIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argClusterId,
		String argName )
	{
		final String S_ProcName = "deleteSecClusRoleByUNameIdx";
		boolean permissionGranted = canDeleteSecClusRole(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecClusRoleService().deleteByUNameIdx(argClusterId,
		argName);
	}


	/**
	 *	Delete the SecClusRole instances identified by the key UNameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteSecClusRoleByUNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleByUNameIdxKey argKey )
	{
		final String S_ProcName = "deleteSecClusRoleByUNameIdx";
		boolean permissionGranted = canDeleteSecClusRole(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecClusRoleService().deleteByUNameIdx(argKey.getRequiredClusterId(),
			argKey.getRequiredName());
	}


	/**
	 *	Read the derived SecClusRole record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecClusRole instance to be read.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecClusRole readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "readDerived";
		boolean permissionGranted = canReadSecClusRole(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecSecClusRole retval = schema.getJpaHooksSchema().getSecClusRoleService().find(PKey);
		return(retval);
	}

	/**
	 *	Lock the derived SecClusRole record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecClusRole instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecClusRole lockDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockDerived";
		boolean permissionGranted = canUpdateSecClusRole(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatesecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecSecClusRole retval = schema.getJpaHooksSchema().getSecClusRoleService().lockByIdIdx(PKey);
		return(retval);
	}

	/**
	 *	Read all SecClusRole instances.
	 *
	 *	@param	Authorization	The session authorization information.	
	 *
	 *	@return An array of derived record instances, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecClusRole[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "readAllDerived";
		boolean permissionGranted = canReadSecClusRole(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		List<CFSecJpaSecClusRole> retlist = schema.getJpaHooksSchema().getSecClusRoleService().findAll();
		ICFSecSecClusRole[] retset = new ICFSecSecClusRole[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecClusRole cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read the derived SecClusRole record instance identified by the unique key IdIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecClusRoleId	The SecClusRole key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecClusRole readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecClusRoleId )
	{
		final String S_ProcName = "readDerivedByIdIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecClusRole(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		ICFSecSecClusRole retval = schema.getJpaHooksSchema().getSecClusRoleService().find(argSecClusRoleId);
		if(retval != null && !ICFSecSchema.getSystemId().equals(Authorization.getSecUserId())) {
				ICFSecCluster cluster = retval.getRequiredOwnerCluster();
			CFLibDbKeyHash256 effClusterId = cluster.getRequiredId();
			if (!ICFSecSchema.getSecurityService().isMemberOfClusterGroup(Authorization.getSecUserId(), effClusterId, "readsecclusrole")) {
				retval = null;
			}
		}
		return(retval);
	}

	/**
	 *	Read an array of the derived SecClusRole record instances identified by the duplicate key ClusterIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ClusterId	The SecClusRole key attribute of the instance generating the id.
	 *
	 *	@return An array of derived instances for the specified key, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecClusRole[] readDerivedByClusterIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argClusterId )
	{
		final String S_ProcName = "readDerivedByClusterIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecClusRole(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		List<CFSecJpaSecClusRole> retlist = schema.getJpaHooksSchema().getSecClusRoleService().findByClusterIdx(argClusterId);
		ICFSecSecClusRole[] retset = new ICFSecSecClusRole[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecClusRole cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read an array of the derived SecClusRole record instances identified by the duplicate key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	Name	The SecClusRole key attribute of the instance generating the id.
	 *
	 *	@return An array of derived instances for the specified key, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecClusRole[] readDerivedByNameIdx( ICFSecAuthorization Authorization,
		String argName )
	{
		final String S_ProcName = "readDerivedByNameIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecClusRole(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		List<CFSecJpaSecClusRole> retlist = schema.getJpaHooksSchema().getSecClusRoleService().findByNameIdx(argName);
		ICFSecSecClusRole[] retset = new ICFSecSecClusRole[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecClusRole cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read the derived SecClusRole record instance identified by the unique key UNameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ClusterId	The SecClusRole key attribute of the instance generating the id.
	 *
	 *	@param	Name	The SecClusRole key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecClusRole readDerivedByUNameIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argClusterId,
		String argName )
	{
		final String S_ProcName = "readDerivedByUNameIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecClusRole(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		ICFSecSecClusRole retval = schema.getJpaHooksSchema().getSecClusRoleService().findByUNameIdx(argClusterId,
		argName);
		if(retval != null && !ICFSecSchema.getSystemId().equals(Authorization.getSecUserId())) {
				ICFSecCluster cluster = retval.getRequiredOwnerCluster();
			CFLibDbKeyHash256 effClusterId = cluster.getRequiredId();
			if (!ICFSecSchema.getSecurityService().isMemberOfClusterGroup(Authorization.getSecUserId(), effClusterId, "readsecclusrole")) {
				retval = null;
			}
		}
		return(retval);
	}

	/**
	 *	Read the specific SecClusRole record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecClusRole instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusRole readRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "readRec";
		boolean permissionGranted = canReadSecClusRole(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readRec");
	}

	/**
	 *	Lock the specific SecClusRole record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecClusRole instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusRole lockRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockRec";
		boolean permissionGranted = canUpdateSecClusRole(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatesecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "lockRec");
	}

	/**
	 *	Read all the specific SecClusRole record instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecClusRole instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecClusRole[] readAllRec( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "readAllRec";
		boolean permissionGranted = canReadSecClusRole(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readAllRec");
	}


	/**
	 *	Read the specific SecClusRole record instance identified by the unique key IdIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecClusRoleId	The SecClusRole key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusRole readRecByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecClusRoleId )
	{
		final String S_ProcName = "readRecByIdIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecClusRole(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecByIdIdx");
	}

	/**
	 *	Read an array of the specific SecClusRole record instances identified by the duplicate key ClusterIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ClusterId	The SecClusRole key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusRole[] readRecByClusterIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argClusterId )
	{
		final String S_ProcName = "readRecByClusterIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecClusRole(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecByClusterIdx");
	}

	/**
	 *	Read an array of the specific SecClusRole record instances identified by the duplicate key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	Name	The SecClusRole key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusRole[] readRecByNameIdx( ICFSecAuthorization Authorization,
		String argName )
	{
		final String S_ProcName = "readRecByNameIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecClusRole(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecByNameIdx");
	}

	/**
	 *	Read the specific SecClusRole record instance identified by the unique key UNameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	ClusterId	The SecClusRole key attribute of the instance generating the id.
	 *
	 *	@param	Name	The SecClusRole key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusRole readRecByUNameIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argClusterId,
		String argName )
	{
		final String S_ProcName = "readRecByUNameIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecClusRole(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrole", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecByUNameIdx");
	}
}
