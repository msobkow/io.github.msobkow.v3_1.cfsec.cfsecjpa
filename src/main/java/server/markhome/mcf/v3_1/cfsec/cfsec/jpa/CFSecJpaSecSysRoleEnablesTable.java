
// Description: Java 25 DbIO implementation for SecSysRoleEnables.

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
import server.markhome.mcf.v3_1.cflib.keyhash.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;
import server.markhome.mcf.v3_1.cfsec.cfsecobj.*;
import server.markhome.mcf.v3_1.cfsec.cfsec.jpa.CFSecJpaHooksSchema;

/*
 *	CFSecJpaSecSysRoleEnablesTable database implementation for SecSysRoleEnables
 */
public class CFSecJpaSecSysRoleEnablesTable implements ICFSecSecSysRoleEnablesTable
{
	protected CFSecJpaSchema schema;


	public CFSecJpaSecSysRoleEnablesTable(ICFSecSchema schema) {
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

	protected boolean canCreateSecSysRoleEnables(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "createsecsysroleenables");
		}
		return( permissionGranted );
	}

	protected boolean canReadSecSysRoleEnables(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "readsecsysroleenables");
		}
		return( permissionGranted );
	}

	protected boolean canUpdateSecSysRoleEnables(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "updatesecsysroleenables");
		}
		return( permissionGranted );
	}

	protected boolean canDeleteSecSysRoleEnables(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "deletesecsysroleenables");
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
	public ICFSecSecSysRoleEnables createSecSysRoleEnables( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnables rec )
	{
		final String S_ProcName = "createSecSysRoleEnables";
		boolean permissionGranted = canCreateSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "createsecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			throw new CFLibNullArgumentException(getClass(), "createSecSysRoleEnables", 1, "rec");
		}
		else if (rec instanceof CFSecJpaSecSysRoleEnables) {
			CFSecJpaSecSysRoleEnables jparec = (CFSecJpaSecSysRoleEnables)rec;
			jparec.setCreatedAt(LocalDateTime.now());
			jparec.setUpdatedAt(jparec.getCreatedAt());
			jparec.setCreatedByUserId(Authorization.getSecUserId());
			jparec.setUpdatedByUserId(Authorization.getSecUserId());
			CFSecJpaSecSysRoleEnables retval = schema.getJpaHooksSchema().getSecSysRoleEnablesService().create(jparec);
		return(retval);
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "createSecSysRoleEnables", "rec", rec, "CFSecJpaSecSysRoleEnables");
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
	public ICFSecSecSysRoleEnables updateSecSysRoleEnables( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnables rec )
	{
		final String S_ProcName = "updateSecSysRoleEnables";
		boolean permissionGranted = canUpdateSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatesecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			throw new CFLibNullArgumentException(getClass(), "updateSecSysRoleEnables", 1, "rec");
		}
		else if (rec instanceof CFSecJpaSecSysRoleEnables) {
			CFSecJpaSecSysRoleEnables jparec = (CFSecJpaSecSysRoleEnables)rec;
			jparec.setUpdatedAt(LocalDateTime.now());
			jparec.setUpdatedByUserId(Authorization.getSecUserId());
			CFSecJpaSecSysRoleEnables retval = schema.getJpaHooksSchema().getSecSysRoleEnablesService().update(jparec);
		return(retval);
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "updateSecSysRoleEnables", "rec", rec, "CFSecJpaSecSysRoleEnables");
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
	public void deleteSecSysRoleEnables( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnables rec )
	{
		final String S_ProcName = "deleteSecSysRoleEnables";
		boolean permissionGranted = canDeleteSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			return;
		}
		if (rec instanceof CFSecJpaSecSysRoleEnables) {
			CFSecJpaSecSysRoleEnables jparec = (CFSecJpaSecSysRoleEnables)rec;
			schema.getJpaHooksSchema().getSecSysRoleEnablesService().deleteByIdIdx(jparec.getPKey());
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "deleteSecSysRoleEnables", "rec", rec, "CFSecJpaSecSysRoleEnables");
		}

		throw new CFLibNotImplementedYetException(getClass(), "deleteSecSysRoleEnables");
	}

	/**
	 *	Delete the SecSysRoleEnables instance identified by the primary key attributes.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysRoleId	The SecSysRoleEnables key attribute of the instance generating the id.
	 *
	 *	@param	EnableName	The SecSysRoleEnables key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecSysRoleEnablesByIdIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSecSysRoleId,
		$implIJavaAtomType$ argEnableName )
	{
		final String S_ProcName = "deleteSecSysRoleEnablesByIdIdx";
		boolean permissionGranted = canDeleteSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecSysRoleEnablesService().deleteByIdIdx(argSecSysRoleId,
		argEnableName);
	}

	/**
	 *	Delete the SecSysRoleEnables instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The primary key identifying the instance to be deleted.
	 */
	@Override
	public void deleteSecSysRoleEnablesByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnablesPKey argKey )
	{
		final String S_ProcName = "deleteSecSysRoleEnablesByIdIdx";
		boolean permissionGranted = canDeleteSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecSysRoleEnablesService().deleteByIdIdx(argKey.getRequiredSecSysRoleId(),
			argKey.getRequiredEnableName());
	}

	/**
	 *	Delete the SecSysRoleEnables instances identified by the key SysRoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysRoleId	The SecSysRoleEnables key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecSysRoleEnablesBySysRoleIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSecSysRoleId )
	{
		final String S_ProcName = "deleteSecSysRoleEnablesBySysRoleIdx";
		boolean permissionGranted = canDeleteSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecSysRoleEnablesService().deleteBySysRoleIdx(argSecSysRoleId);
	}


	/**
	 *	Delete the SecSysRoleEnables instances identified by the key SysRoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteSecSysRoleEnablesBySysRoleIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnablesBySysRoleIdxKey argKey )
	{
		final String S_ProcName = "deleteSecSysRoleEnablesBySysRoleIdx";
		boolean permissionGranted = canDeleteSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecSysRoleEnablesService().deleteBySysRoleIdx(argKey.getRequiredSecSysRoleId());
	}

	/**
	 *	Delete the SecSysRoleEnables instances identified by the key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EnableName	The SecSysRoleEnables key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecSysRoleEnablesByNameIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argEnableName )
	{
		final String S_ProcName = "deleteSecSysRoleEnablesByNameIdx";
		boolean permissionGranted = canDeleteSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecSysRoleEnablesService().deleteByNameIdx(argEnableName);
	}


	/**
	 *	Delete the SecSysRoleEnables instances identified by the key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteSecSysRoleEnablesByNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnablesByNameIdxKey argKey )
	{
		final String S_ProcName = "deleteSecSysRoleEnablesByNameIdx";
		boolean permissionGranted = canDeleteSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletesecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecSysRoleEnablesService().deleteByNameIdx(argKey.getRequiredEnableName());
	}


	/**
	 *	Read the derived SecSysRoleEnables record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecSysRoleEnables instance to be read.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecSysRoleEnables readDerived( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnablesPKey PKey )
	{
		final String S_ProcName = "readDerived";
		boolean permissionGranted = canReadSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecSecSysRoleEnables retval = schema.getJpaHooksSchema().getSecSysRoleEnablesService().find(PKey);
		return(retval);
	}

	/**
	 *	Read the derived SecSysRoleEnables record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecSysRoleEnables readDerived( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSecSysRoleId,
		$implIJavaAtomType$ argEnableName )
	{
		final String S_ProcName = "readDerived";
		boolean permissionGranted = canReadSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecSecSysRoleEnables retval = schema.getJpaHooksSchema().getSecSysRoleEnablesService().find(argSecSysRoleId,
		argEnableName);
		return(retval);
	}

	/**
	 *	Lock the derived SecSysRoleEnables record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecSysRoleEnables instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecSysRoleEnables lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnablesPKey PKey )
	{
		final String S_ProcName = "lockDerived";
		boolean permissionGranted = canUpdateSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatesecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecSecSysRoleEnables retval = schema.getJpaHooksSchema().getSecSysRoleEnablesService().lockByIdIdx(PKey);
		return(retval);
	}

	/**
	 *	Read all SecSysRoleEnables instances.
	 *
	 *	@param	Authorization	The session authorization information.	
	 *
	 *	@return An array of derived record instances, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecSysRoleEnables[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "readAllDerived";
		boolean permissionGranted = canReadSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		List<CFSecJpaSecSysRoleEnables> retlist = schema.getJpaHooksSchema().getSecSysRoleEnablesService().findAll();
		ICFSecSecSysRoleEnables[] retset = new ICFSecSecSysRoleEnables[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecSysRoleEnables cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read the derived SecSysRoleEnables record instance identified by the unique key IdIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysRoleId	The SecSysRoleEnables key attribute of the instance generating the id.
	 *
	 *	@param	EnableName	The SecSysRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecSysRoleEnables readDerivedByIdIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSecSysRoleId,
		$implIJavaAtomType$ argEnableName )
	{
		final String S_ProcName = "readDerivedByIdIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecSysRoleEnables(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		ICFSecSecSysRoleEnables retval = schema.getJpaHooksSchema().getSecSysRoleEnablesService().find(argSecSysRoleId,
		argEnableName);
		return(retval);
	}

	/**
	 *	Read an array of the derived SecSysRoleEnables record instances identified by the duplicate key SysRoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysRoleId	The SecSysRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return An array of derived instances for the specified key, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecSysRoleEnables[] readDerivedBySysRoleIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSecSysRoleId )
	{
		final String S_ProcName = "readDerivedBySysRoleIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecSysRoleEnables(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		List<CFSecJpaSecSysRoleEnables> retlist = schema.getJpaHooksSchema().getSecSysRoleEnablesService().findBySysRoleIdx(argSecSysRoleId);
		ICFSecSecSysRoleEnables[] retset = new ICFSecSecSysRoleEnables[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecSysRoleEnables cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read an array of the derived SecSysRoleEnables record instances identified by the duplicate key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EnableName	The SecSysRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return An array of derived instances for the specified key, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecSysRoleEnables[] readDerivedByNameIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argEnableName )
	{
		final String S_ProcName = "readDerivedByNameIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecSysRoleEnables(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		List<CFSecJpaSecSysRoleEnables> retlist = schema.getJpaHooksSchema().getSecSysRoleEnablesService().findByNameIdx(argEnableName);
		ICFSecSecSysRoleEnables[] retset = new ICFSecSecSysRoleEnables[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecSysRoleEnables cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read the specific SecSysRoleEnables record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecSysRoleEnables instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysRoleEnables readRec( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnablesPKey PKey )
	{
		final String S_ProcName = "readRec";
		boolean permissionGranted = canReadSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readRec");
	}

	/**
	 *	Read the specific SecSysRoleEnables record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecSysRoleEnables instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysRoleEnables readRec( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSecSysRoleId,
		$implIJavaAtomType$ argEnableName )
	{
		final String S_ProcName = "readRec";
		boolean permissionGranted = canReadSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readRec-args");
	}

	/**
	 *	Lock the specific SecSysRoleEnables record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecSysRoleEnables instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysRoleEnables lockRec( ICFSecAuthorization Authorization,
		ICFSecSecSysRoleEnablesPKey PKey )
	{
		final String S_ProcName = "lockRec";
		boolean permissionGranted = canUpdateSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatesecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "lockRec");
	}

	/**
	 *	Read all the specific SecSysRoleEnables record instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecSysRoleEnables instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecSysRoleEnables[] readAllRec( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "readAllRec";
		boolean permissionGranted = canReadSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readAllRec");
	}


	/**
	 *	Read a page of all the specific SecSysRoleEnables record instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecSysRoleEnables instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecSysRoleEnables[] pageAllRec( ICFSecAuthorization Authorization,
		$implIJavaOptAtomType$ priorSecSysRoleId,
		$implIJavaOptAtomType$ priorEnableName )
	{
		final String S_ProcName = "pageAllRec";
		boolean permissionGranted = canReadSecSysRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "pageAllRec");
	}

	/**
	 *	Read the specific SecSysRoleEnables record instance identified by the unique key IdIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysRoleId	The SecSysRoleEnables key attribute of the instance generating the id.
	 *
	 *	@param	EnableName	The SecSysRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysRoleEnables readRecByIdIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSecSysRoleId,
		$implIJavaAtomType$ argEnableName )
	{
		final String S_ProcName = "readRecByIdIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecSysRoleEnables(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecByIdIdx");
	}

	/**
	 *	Read an array of the specific SecSysRoleEnables record instances identified by the duplicate key SysRoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysRoleId	The SecSysRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysRoleEnables[] readRecBySysRoleIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSecSysRoleId )
	{
		final String S_ProcName = "readRecBySysRoleIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecSysRoleEnables(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecBySysRoleIdx");
	}

	/**
	 *	Read an array of the specific SecSysRoleEnables record instances identified by the duplicate key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EnableName	The SecSysRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysRoleEnables[] readRecByNameIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argEnableName )
	{
		final String S_ProcName = "readRecByNameIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecSysRoleEnables(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecByNameIdx");
	}

	/**
	 *	Read a page array of the specific SecSysRoleEnables record instances identified by the duplicate key SysRoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecSysRoleId	The SecSysRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysRoleEnables[] pageRecBySysRoleIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSecSysRoleId,
		$implIJavaOptAtomType$ priorSecSysRoleId,
		$implIJavaOptAtomType$ priorEnableName )
	{
		final String S_ProcName = "pageRecBySysRoleIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecSysRoleEnables(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "pageRecBySysRoleIdx");
	}

	/**
	 *	Read a page array of the specific SecSysRoleEnables record instances identified by the duplicate key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EnableName	The SecSysRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecSysRoleEnables[] pageRecByNameIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argEnableName,
		$implIJavaOptAtomType$ priorSecSysRoleId,
		$implIJavaOptAtomType$ priorEnableName )
	{
		final String S_ProcName = "pageRecByNameIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadSecSysRoleEnables(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readsecsysroleenables", ICFSecSchema.SCHEMA_NAME, ICFSecSecSysRoleEnablesTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "pageRecByNameIdx");
	}
}
