
// Description: Java 25 DbIO implementation for SecClusRoleMemb.

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
 *	CFSecJpaSecClusRoleMembTable database implementation for SecClusRoleMemb
 */
public class CFSecJpaSecClusRoleMembTable implements ICFSecSecClusRoleMembTable
{
	protected CFSecJpaSchema schema;


	public CFSecJpaSecClusRoleMembTable(ICFSecSchema schema) {
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

	protected boolean canCreateSecClusRoleMemb(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfClusterGroup(Authorization.getSecUserId(), Authorization.getSecClusterId(), "createsecclusrolememb");
		}
		return( permissionGranted );
	}

	protected boolean canReadSecClusRoleMemb(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfClusterGroup(Authorization.getSecUserId(), Authorization.getSecClusterId(), "readsecclusrolememb");
		}
		return( permissionGranted );
	}

	protected boolean canUpdateSecClusRoleMemb(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfClusterGroup(Authorization.getSecUserId(), ICFSecSchema.getSysClusterId(), "updatesecclusrolememb");
		}
		return( permissionGranted );
	}

	protected boolean canDeleteSecClusRoleMemb(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfClusterGroup(Authorization.getSecUserId(), ICFSecSchema.getSysClusterId(), "deletesecclusrolememb");
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
	public ICFSecSecClusRoleMemb createSecClusRoleMemb( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMemb rec )
	{
		final String S_ProcName = "createSecClusRoleMemb";
		boolean permissionGranted = canCreateSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "createsecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			throw new CFLibNullArgumentException(getClass(), "createSecClusRoleMemb", 1, "rec");
		}
		else if (rec instanceof CFSecJpaSecClusRoleMemb) {
			CFSecJpaSecClusRoleMemb jparec = (CFSecJpaSecClusRoleMemb)rec;
			jparec.setCreatedAt(LocalDateTime.now());
			jparec.setUpdatedAt(jparec.getCreatedAt());
			jparec.setCreatedByUserId(Authorization.getSecUserId());
			jparec.setUpdatedByUserId(Authorization.getSecUserId());
			CFSecJpaSecClusRoleMemb retval = schema.getJpaHooksSchema().getSecClusRoleMembService().create(jparec);
		return(retval);
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "createSecClusRoleMemb", "rec", rec, "CFSecJpaSecClusRoleMemb");
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
	public ICFSecSecClusRoleMemb updateSecClusRoleMemb( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMemb rec )
	{
		final String S_ProcName = "updateSecClusRoleMemb";
		boolean permissionGranted = canUpdateSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatesecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			throw new CFLibNullArgumentException(getClass(), "updateSecClusRoleMemb", 1, "rec");
		}
		else if (rec instanceof CFSecJpaSecClusRoleMemb) {
			CFSecJpaSecClusRoleMemb jparec = (CFSecJpaSecClusRoleMemb)rec;
			jparec.setUpdatedAt(LocalDateTime.now());
			jparec.setUpdatedByUserId(Authorization.getSecUserId());
			CFSecJpaSecClusRoleMemb retval = schema.getJpaHooksSchema().getSecClusRoleMembService().update(jparec);
		return(retval);
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "updateSecClusRoleMemb", "rec", rec, "CFSecJpaSecClusRoleMemb");
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
	public void deleteSecClusRoleMemb( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMemb rec )
	{
		final String S_ProcName = "deleteSecClusRoleMemb";
		boolean permissionGranted = canDeleteSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			return;
		}
		if (rec instanceof CFSecJpaSecClusRoleMemb) {
			CFSecJpaSecClusRoleMemb jparec = (CFSecJpaSecClusRoleMemb)rec;
			schema.getJpaHooksSchema().getSecClusRoleMembService().deleteByIdIdx(jparec.getPKey());
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "deleteSecClusRoleMemb", "rec", rec, "CFSecJpaSecClusRoleMemb");
		}

		throw new CFLibNotImplementedYetException(getClass(), "deleteSecClusRoleMemb");
	}

	/**
	 *	Delete the SecClusRoleMemb instance identified by the primary key attributes.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecClusRoleId	The SecClusRoleMemb key attribute of the instance generating the id.
	 *
	 *	@param	LoginId	The SecClusRoleMemb key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecClusRoleMembByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecClusRoleId,
		String argLoginId )
	{
		final String S_ProcName = "deleteSecClusRoleMembByIdIdx";
		boolean permissionGranted = canDeleteSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecClusRoleMembService().deleteByIdIdx(argSecClusRoleId,
		argLoginId);
	}

	/**
	 *	Delete the SecClusRoleMemb instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The primary key identifying the instance to be deleted.
	 */
	@Override
	public void deleteSecClusRoleMembByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMembPKey argKey )
	{
		final String S_ProcName = "deleteSecClusRoleMembByIdIdx";
		boolean permissionGranted = canDeleteSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecClusRoleMembService().deleteByIdIdx(argKey.getRequiredSecClusRoleId(),
			argKey.getRequiredLoginId());
	}

	/**
	 *	Delete the SecClusRoleMemb instances identified by the key ClusRoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecClusRoleId	The SecClusRoleMemb key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecClusRoleMembByClusRoleIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecClusRoleId )
	{
		final String S_ProcName = "deleteSecClusRoleMembByClusRoleIdx";
		boolean permissionGranted = canDeleteSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecClusRoleMembService().deleteByClusRoleIdx(argSecClusRoleId);
	}


	/**
	 *	Delete the SecClusRoleMemb instances identified by the key ClusRoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteSecClusRoleMembByClusRoleIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMembByClusRoleIdxKey argKey )
	{
		final String S_ProcName = "deleteSecClusRoleMembByClusRoleIdx";
		boolean permissionGranted = canDeleteSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecClusRoleMembService().deleteByClusRoleIdx(argKey.getRequiredSecClusRoleId());
	}

	/**
	 *	Delete the SecClusRoleMemb instances identified by the key LoginIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	LoginId	The SecClusRoleMemb key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecClusRoleMembByLoginIdx( ICFSecAuthorization Authorization,
		String argLoginId )
	{
		final String S_ProcName = "deleteSecClusRoleMembByLoginIdx";
		boolean permissionGranted = canDeleteSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecClusRoleMembService().deleteByLoginIdx(argLoginId);
	}


	/**
	 *	Delete the SecClusRoleMemb instances identified by the key LoginIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteSecClusRoleMembByLoginIdx( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMembByLoginIdxKey argKey )
	{
		final String S_ProcName = "deleteSecClusRoleMembByLoginIdx";
		boolean permissionGranted = canDeleteSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecClusRoleMembService().deleteByLoginIdx(argKey.getRequiredLoginId());
	}


	/**
	 *	Read the derived SecClusRoleMemb record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecClusRoleMemb instance to be read.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecClusRoleMemb readDerived( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMembPKey PKey )
	{
		final String S_ProcName = "readDerived";
		boolean permissionGranted = canReadSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecSecClusRoleMemb retval = schema.getJpaHooksSchema().getSecClusRoleMembService().find(PKey);
		return(retval);
	}

	/**
	 *	Read the derived SecClusRoleMemb record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecClusRoleMemb readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecClusRoleId,
		String argLoginId )
	{
		final String S_ProcName = "readDerived";
		boolean permissionGranted = canReadSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecSecClusRoleMemb retval = schema.getJpaHooksSchema().getSecClusRoleMembService().find(argSecClusRoleId,
		argLoginId);
		return(retval);
	}

	/**
	 *	Lock the derived SecClusRoleMemb record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecClusRoleMemb instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecClusRoleMemb lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMembPKey PKey )
	{
		final String S_ProcName = "lockDerived";
		boolean permissionGranted = canUpdateSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatesecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecSecClusRoleMemb retval = schema.getJpaHooksSchema().getSecClusRoleMembService().lockByIdIdx(PKey);
		return(retval);
	}

	/**
	 *	Read all SecClusRoleMemb instances.
	 *
	 *	@param	Authorization	The session authorization information.	
	 *
	 *	@return An array of derived record instances, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecClusRoleMemb[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "readAllDerived";
		boolean permissionGranted = canReadSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		List<CFSecJpaSecClusRoleMemb> retlist = schema.getJpaHooksSchema().getSecClusRoleMembService().findAll();
		ICFSecSecClusRoleMemb[] retset = new ICFSecSecClusRoleMemb[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecClusRoleMemb cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read the derived SecClusRoleMemb record instance identified by the unique key IdIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecClusRoleId	The SecClusRoleMemb key attribute of the instance generating the id.
	 *
	 *	@param	LoginId	The SecClusRoleMemb key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecClusRoleMemb readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecClusRoleId,
		String argLoginId )
	{
		final String S_ProcName = "readDerivedByIdIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecClusRoleMemb(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		ICFSecSecClusRoleMemb retval = schema.getJpaHooksSchema().getSecClusRoleMembService().find(argSecClusRoleId,
		argLoginId);
		if(retval != null && !ICFSecSchema.getSystemId().equals(Authorization.getSecUserId())) {
				ICFSecCluster cluster = retval.getRequiredContainerRole().getRequiredOwnerCluster();
			CFLibDbKeyHash256 effClusterId = cluster.getRequiredId();
			if (!ICFSecSchema.getSecurityService().isMemberOfClusterGroup(Authorization.getSecUserId(), effClusterId, "readsecclusrolememb")) {
				retval = null;
			}
		}
		return(retval);
	}

	/**
	 *	Read an array of the derived SecClusRoleMemb record instances identified by the duplicate key ClusRoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecClusRoleId	The SecClusRoleMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived instances for the specified key, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecClusRoleMemb[] readDerivedByClusRoleIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecClusRoleId )
	{
		final String S_ProcName = "readDerivedByClusRoleIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecClusRoleMemb(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		List<CFSecJpaSecClusRoleMemb> retlist = schema.getJpaHooksSchema().getSecClusRoleMembService().findByClusRoleIdx(argSecClusRoleId);
		ICFSecSecClusRoleMemb[] retset = new ICFSecSecClusRoleMemb[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecClusRoleMemb cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read an array of the derived SecClusRoleMemb record instances identified by the duplicate key LoginIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	LoginId	The SecClusRoleMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived instances for the specified key, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecClusRoleMemb[] readDerivedByLoginIdx( ICFSecAuthorization Authorization,
		String argLoginId )
	{
		final String S_ProcName = "readDerivedByLoginIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecClusRoleMemb(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		List<CFSecJpaSecClusRoleMemb> retlist = schema.getJpaHooksSchema().getSecClusRoleMembService().findByLoginIdx(argLoginId);
		ICFSecSecClusRoleMemb[] retset = new ICFSecSecClusRoleMemb[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecClusRoleMemb cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read the specific SecClusRoleMemb record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecClusRoleMemb instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusRoleMemb readRec( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMembPKey PKey )
	{
		final String S_ProcName = "readRec";
		boolean permissionGranted = canReadSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readRec");
	}

	/**
	 *	Read the specific SecClusRoleMemb record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecClusRoleMemb instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusRoleMemb readRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecClusRoleId,
		String argLoginId )
	{
		final String S_ProcName = "readRec";
		boolean permissionGranted = canReadSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readRec-args");
	}

	/**
	 *	Lock the specific SecClusRoleMemb record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecClusRoleMemb instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusRoleMemb lockRec( ICFSecAuthorization Authorization,
		ICFSecSecClusRoleMembPKey PKey )
	{
		final String S_ProcName = "lockRec";
		boolean permissionGranted = canUpdateSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatesecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "lockRec");
	}

	/**
	 *	Read all the specific SecClusRoleMemb record instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecClusRoleMemb instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecClusRoleMemb[] readAllRec( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "readAllRec";
		boolean permissionGranted = canReadSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readAllRec");
	}


	/**
	 *	Read a page of all the specific SecClusRoleMemb record instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecClusRoleMemb instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecClusRoleMemb[] pageAllRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecClusRoleId,
		String priorLoginId )
	{
		final String S_ProcName = "pageAllRec";
		boolean permissionGranted = canReadSecClusRoleMemb(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "pageAllRec");
	}

	/**
	 *	Read the specific SecClusRoleMemb record instance identified by the unique key IdIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecClusRoleId	The SecClusRoleMemb key attribute of the instance generating the id.
	 *
	 *	@param	LoginId	The SecClusRoleMemb key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusRoleMemb readRecByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecClusRoleId,
		String argLoginId )
	{
		final String S_ProcName = "readRecByIdIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecClusRoleMemb(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecByIdIdx");
	}

	/**
	 *	Read an array of the specific SecClusRoleMemb record instances identified by the duplicate key ClusRoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecClusRoleId	The SecClusRoleMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusRoleMemb[] readRecByClusRoleIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecClusRoleId )
	{
		final String S_ProcName = "readRecByClusRoleIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecClusRoleMemb(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecByClusRoleIdx");
	}

	/**
	 *	Read an array of the specific SecClusRoleMemb record instances identified by the duplicate key LoginIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	LoginId	The SecClusRoleMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusRoleMemb[] readRecByLoginIdx( ICFSecAuthorization Authorization,
		String argLoginId )
	{
		final String S_ProcName = "readRecByLoginIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecClusRoleMemb(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecByLoginIdx");
	}

	/**
	 *	Read a page array of the specific SecClusRoleMemb record instances identified by the duplicate key ClusRoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecClusRoleId	The SecClusRoleMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusRoleMemb[] pageRecByClusRoleIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecClusRoleId,
		CFLibDbKeyHash256 priorSecClusRoleId,
		String priorLoginId )
	{
		final String S_ProcName = "pageRecByClusRoleIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecClusRoleMemb(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "pageRecByClusRoleIdx");
	}

	/**
	 *	Read a page array of the specific SecClusRoleMemb record instances identified by the duplicate key LoginIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	LoginId	The SecClusRoleMemb key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecClusRoleMemb[] pageRecByLoginIdx( ICFSecAuthorization Authorization,
		String argLoginId,
		CFLibDbKeyHash256 priorSecClusRoleId,
		String priorLoginId )
	{
		final String S_ProcName = "pageRecByLoginIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecClusRoleMemb(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecclusrolememb", ICFSecSchema.SCHEMA_NAME, ICFSecSecClusRoleMembTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "pageRecByLoginIdx");
	}
}
