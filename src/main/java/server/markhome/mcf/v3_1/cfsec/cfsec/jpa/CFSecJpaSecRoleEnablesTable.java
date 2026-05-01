
// Description: Java 25 DbIO implementation for SecRoleEnables.

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
 *	CFSecJpaSecRoleEnablesTable database implementation for SecRoleEnables
 */
public class CFSecJpaSecRoleEnablesTable implements ICFSecSecRoleEnablesTable
{
	protected CFSecJpaSchema schema;


	public CFSecJpaSecRoleEnablesTable(ICFSecSchema schema) {
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

	protected boolean canCreateSecRoleEnables(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "createsecroleenables");
		}
		return( permissionGranted );
	}

	protected boolean canReadSecRoleEnables(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "readsecroleenables");
		}
		return( permissionGranted );
	}

	protected boolean canUpdateSecRoleEnables(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "updatesecroleenables");
		}
		return( permissionGranted );
	}

	protected boolean canDeleteSecRoleEnables(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "deletesecroleenables");
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
	public ICFSecSecRoleEnables createSecRoleEnables( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnables rec )
	{
		final String S_ProcName = "createSecRoleEnables";
		boolean permissionGranted = canCreateSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "createsecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			throw new CFLibNullArgumentException(getClass(), "createSecRoleEnables", 1, "rec");
		}
		else if (rec instanceof CFSecJpaSecRoleEnables) {
			CFSecJpaSecRoleEnables jparec = (CFSecJpaSecRoleEnables)rec;
			CFSecJpaSecRoleEnables retval = schema.getJpaHooksSchema().getSecRoleEnablesService().create(jparec);
		return( retval );
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "createSecRoleEnables", "rec", rec, "CFSecJpaSecRoleEnables");
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
	public ICFSecSecRoleEnables updateSecRoleEnables( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnables rec )
	{
		final String S_ProcName = "updateSecRoleEnables";
		boolean permissionGranted = canUpdateSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "updatesecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			throw new CFLibNullArgumentException(getClass(), "updateSecRoleEnables", 1, "rec");
		}
		else if (rec instanceof CFSecJpaSecRoleEnables) {
			CFSecJpaSecRoleEnables jparec = (CFSecJpaSecRoleEnables)rec;
			CFSecJpaSecRoleEnables retval = schema.getJpaHooksSchema().getSecRoleEnablesService().update(jparec);
		return( retval );
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "updateSecRoleEnables", "rec", rec, "CFSecJpaSecRoleEnables");
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
	public void deleteSecRoleEnables( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnables rec )
	{
		final String S_ProcName = "deleteSecRoleEnables";
		boolean permissionGranted = canDeleteSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "deletesecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			return;
		}
		if (rec instanceof CFSecJpaSecRoleEnables) {
			CFSecJpaSecRoleEnables jparec = (CFSecJpaSecRoleEnables)rec;
			schema.getJpaHooksSchema().getSecRoleEnablesService().deleteByIdIdx(jparec.getPKey());
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "deleteSecRoleEnables", "rec", rec, "CFSecJpaSecRoleEnables");
		}

		throw new CFLibNotImplementedYetException(getClass(), "deleteSecRoleEnables");
	}

	/**
	 *	Delete the SecRoleEnables instance identified by the primary key attributes.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecRoleId	The SecRoleEnables key attribute of the instance generating the id.
	 *
	 *	@param	EnableName	The SecRoleEnables key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecRoleEnablesByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecRoleId,
		String argEnableName )
	{
		final String S_ProcName = "deleteSecRoleEnablesByIdIdx";
		boolean permissionGranted = canDeleteSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "deletesecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecRoleEnablesService().deleteByIdIdx(argSecRoleId,
		argEnableName);
	}

	/**
	 *	Delete the SecRoleEnables instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The primary key identifying the instance to be deleted.
	 */
	@Override
	public void deleteSecRoleEnablesByIdIdx( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnablesPKey argKey )
	{
		final String S_ProcName = "deleteSecRoleEnablesByIdIdx";
		boolean permissionGranted = canDeleteSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "deletesecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecRoleEnablesService().deleteByIdIdx(argKey.getRequiredSecRoleId(),
			argKey.getRequiredEnableName());
	}

	/**
	 *	Delete the SecRoleEnables instances identified by the key RoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecRoleId	The SecRoleEnables key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecRoleEnablesByRoleIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecRoleId )
	{
		final String S_ProcName = "deleteSecRoleEnablesByRoleIdx";
		boolean permissionGranted = canDeleteSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "deletesecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecRoleEnablesService().deleteByRoleIdx(argSecRoleId);
	}


	/**
	 *	Delete the SecRoleEnables instances identified by the key RoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteSecRoleEnablesByRoleIdx( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnablesByRoleIdxKey argKey )
	{
		final String S_ProcName = "deleteSecRoleEnablesByRoleIdx";
		boolean permissionGranted = canDeleteSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "deletesecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecRoleEnablesService().deleteByRoleIdx(argKey.getRequiredSecRoleId());
	}

	/**
	 *	Delete the SecRoleEnables instances identified by the key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EnableName	The SecRoleEnables key attribute of the instance generating the id.
	 */
	@Override
	public void deleteSecRoleEnablesByNameIdx( ICFSecAuthorization Authorization,
		String argEnableName )
	{
		final String S_ProcName = "deleteSecRoleEnablesByNameIdx";
		boolean permissionGranted = canDeleteSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "deletesecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecRoleEnablesService().deleteByNameIdx(argEnableName);
	}


	/**
	 *	Delete the SecRoleEnables instances identified by the key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteSecRoleEnablesByNameIdx( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnablesByNameIdxKey argKey )
	{
		final String S_ProcName = "deleteSecRoleEnablesByNameIdx";
		boolean permissionGranted = canDeleteSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "deletesecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getSecRoleEnablesService().deleteByNameIdx(argKey.getRequiredEnableName());
	}


	/**
	 *	Read the derived SecRoleEnables record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecRoleEnables instance to be read.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecRoleEnables readDerived( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnablesPKey PKey )
	{
		final String S_ProcName = "readDerived";
		boolean permissionGranted = canReadSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "readsecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecSecRoleEnables retval = schema.getJpaHooksSchema().getSecRoleEnablesService().find(PKey);
		return( retval );
	}

	/**
	 *	Read the derived SecRoleEnables record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecRoleEnables readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecRoleId,
		String argEnableName )
	{
		final String S_ProcName = "readDerived";
		boolean permissionGranted = canReadSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "readsecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecSecRoleEnables retval = schema.getJpaHooksSchema().getSecRoleEnablesService().find(argSecRoleId,
		argEnableName);
		return( retval );
	}

	/**
	 *	Lock the derived SecRoleEnables record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecRoleEnables instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecRoleEnables lockDerived( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnablesPKey PKey )
	{
		final String S_ProcName = "lockDerived";
		boolean permissionGranted = canUpdateSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "updatesecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecSecRoleEnables retval = schema.getJpaHooksSchema().getSecRoleEnablesService().lockByIdIdx(PKey);
		return( retval );
	}

	/**
	 *	Read all SecRoleEnables instances.
	 *
	 *	@param	Authorization	The session authorization information.	
	 *
	 *	@return An array of derived record instances, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecRoleEnables[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "readAllDerived";
		boolean permissionGranted = canReadSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "readsecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		List<CFSecJpaSecRoleEnables> retlist = schema.getJpaHooksSchema().getSecRoleEnablesService().findAll();
		ICFSecSecRoleEnables[] retset = new ICFSecSecRoleEnables[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecRoleEnables cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read the derived SecRoleEnables record instance identified by the unique key IdIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecRoleId	The SecRoleEnables key attribute of the instance generating the id.
	 *
	 *	@param	EnableName	The SecRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecSecRoleEnables readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecRoleId,
		String argEnableName )
	{
		final String S_ProcName = "readDerivedByIdIdx";
		boolean permissionGranted = canReadSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "readsecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecSecRoleEnables retval = schema.getJpaHooksSchema().getSecRoleEnablesService().find(argSecRoleId,
		argEnableName);
		return( retval );
	}

	/**
	 *	Read an array of the derived SecRoleEnables record instances identified by the duplicate key RoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecRoleId	The SecRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return An array of derived instances for the specified key, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecRoleEnables[] readDerivedByRoleIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecRoleId )
	{
		final String S_ProcName = "readDerivedByRoleIdx";
		boolean permissionGranted = canReadSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "readsecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		List<CFSecJpaSecRoleEnables> retlist = schema.getJpaHooksSchema().getSecRoleEnablesService().findByRoleIdx(argSecRoleId);
		ICFSecSecRoleEnables[] retset = new ICFSecSecRoleEnables[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecRoleEnables cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read an array of the derived SecRoleEnables record instances identified by the duplicate key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EnableName	The SecRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return An array of derived instances for the specified key, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecSecRoleEnables[] readDerivedByNameIdx( ICFSecAuthorization Authorization,
		String argEnableName )
	{
		final String S_ProcName = "readDerivedByNameIdx";
		boolean permissionGranted = canReadSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "readsecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		List<CFSecJpaSecRoleEnables> retlist = schema.getJpaHooksSchema().getSecRoleEnablesService().findByNameIdx(argEnableName);
		ICFSecSecRoleEnables[] retset = new ICFSecSecRoleEnables[retlist.size()];
		int idx = 0;
		for (CFSecJpaSecRoleEnables cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read the specific SecRoleEnables record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecRoleEnables instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecRoleEnables readRec( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnablesPKey PKey )
	{
		final String S_ProcName = "readRec";
		boolean permissionGranted = canReadSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "readsecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readRec");
	}

	/**
	 *	Read the specific SecRoleEnables record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecRoleEnables instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecRoleEnables readRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecRoleId,
		String argEnableName )
	{
		final String S_ProcName = "readRec";
		boolean permissionGranted = canReadSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "readsecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readRec-args");
	}

	/**
	 *	Lock the specific SecRoleEnables record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the SecRoleEnables instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecRoleEnables lockRec( ICFSecAuthorization Authorization,
		ICFSecSecRoleEnablesPKey PKey )
	{
		final String S_ProcName = "lockRec";
		boolean permissionGranted = canUpdateSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "updatesecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "lockRec");
	}

	/**
	 *	Read all the specific SecRoleEnables record instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecRoleEnables instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecRoleEnables[] readAllRec( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "readAllRec";
		boolean permissionGranted = canReadSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "readsecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readAllRec");
	}


	/**
	 *	Read a page of all the specific SecRoleEnables record instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecRoleEnables instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecSecRoleEnables[] pageAllRec( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecRoleId,
		String priorEnableName )
	{
		final String S_ProcName = "pageAllRec";
		boolean permissionGranted = canReadSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "readsecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "pageAllRec");
	}

	/**
	 *	Read the specific SecRoleEnables record instance identified by the unique key IdIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecRoleId	The SecRoleEnables key attribute of the instance generating the id.
	 *
	 *	@param	EnableName	The SecRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecRoleEnables readRecByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecRoleId,
		String argEnableName )
	{
		final String S_ProcName = "readRecByIdIdx";
		boolean permissionGranted = canReadSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "readsecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readRecByIdIdx");
	}

	/**
	 *	Read an array of the specific SecRoleEnables record instances identified by the duplicate key RoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecRoleId	The SecRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecRoleEnables[] readRecByRoleIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecRoleId )
	{
		final String S_ProcName = "readRecByRoleIdx";
		boolean permissionGranted = canReadSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "readsecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readRecByRoleIdx");
	}

	/**
	 *	Read an array of the specific SecRoleEnables record instances identified by the duplicate key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EnableName	The SecRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecRoleEnables[] readRecByNameIdx( ICFSecAuthorization Authorization,
		String argEnableName )
	{
		final String S_ProcName = "readRecByNameIdx";
		boolean permissionGranted = canReadSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "readsecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readRecByNameIdx");
	}

	/**
	 *	Read a page array of the specific SecRoleEnables record instances identified by the duplicate key RoleIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SecRoleId	The SecRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecRoleEnables[] pageRecByRoleIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecRoleId,
		CFLibDbKeyHash256 priorSecRoleId,
		String priorEnableName )
	{
		final String S_ProcName = "pageRecByRoleIdx";
		boolean permissionGranted = canReadSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "readsecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "pageRecByRoleIdx");
	}

	/**
	 *	Read a page array of the specific SecRoleEnables record instances identified by the duplicate key NameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EnableName	The SecRoleEnables key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecSecRoleEnables[] pageRecByNameIdx( ICFSecAuthorization Authorization,
		String argEnableName,
		CFLibDbKeyHash256 priorSecRoleId,
		String priorEnableName )
	{
		final String S_ProcName = "pageRecByNameIdx";
		boolean permissionGranted = canReadSecRoleEnables(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, ICFSecSchema.SCHEMA_NAME, ICFSecSecRoleEnablesTable.TABLE_NAME, "readsecroleenables", Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "pageRecByNameIdx");
	}
}
