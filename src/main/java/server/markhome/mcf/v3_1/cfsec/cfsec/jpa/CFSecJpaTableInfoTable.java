
// Description: Java 25 DbIO implementation for TableInfo.

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
 *	CFSecJpaTableInfoTable database implementation for TableInfo
 */
public class CFSecJpaTableInfoTable implements ICFSecTableInfoTable
{
	protected CFSecJpaSchema schema;


	public CFSecJpaTableInfoTable(ICFSecSchema schema) {
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

	protected boolean canCreateTableInfo(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "createtableinfo");
		}
		return( permissionGranted );
	}

	protected boolean canReadTableInfo(String S_ProcName, ICFSecAuthorization Authorization) {
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
		// SecScope Global means anyone can read the table any time
		permissionGranted = true;
		return( permissionGranted );
	}

	protected boolean canUpdateTableInfo(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "updatetableinfo");
		}
		return( permissionGranted );
	}

	protected boolean canDeleteTableInfo(String S_ProcName, ICFSecAuthorization Authorization) {
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
			permissionGranted = ICFSecSchema.getSecurityService().isMemberOfSystemGroup(Authorization.getSecUserId(), "deletetableinfo");
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
	public ICFSecTableInfo createTableInfo( ICFSecAuthorization Authorization,
		ICFSecTableInfo rec )
	{
		final String S_ProcName = "createTableInfo";
		boolean permissionGranted = canCreateTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "createtableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			throw new CFLibNullArgumentException(getClass(), "createTableInfo", 1, "rec");
		}
		else if (rec instanceof CFSecJpaTableInfo) {
			CFSecJpaTableInfo jparec = (CFSecJpaTableInfo)rec;
			CFSecJpaTableInfo retval = schema.getJpaHooksSchema().getTableInfoService().create(jparec);
		return(retval);
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "createTableInfo", "rec", rec, "CFSecJpaTableInfo");
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
	public ICFSecTableInfo updateTableInfo( ICFSecAuthorization Authorization,
		ICFSecTableInfo rec )
	{
		final String S_ProcName = "updateTableInfo";
		boolean permissionGranted = canUpdateTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatetableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			throw new CFLibNullArgumentException(getClass(), "updateTableInfo", 1, "rec");
		}
		else if (rec instanceof CFSecJpaTableInfo) {
			CFSecJpaTableInfo jparec = (CFSecJpaTableInfo)rec;
			CFSecJpaTableInfo retval = schema.getJpaHooksSchema().getTableInfoService().update(jparec);
		return(retval);
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "updateTableInfo", "rec", rec, "CFSecJpaTableInfo");
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
	public void deleteTableInfo( ICFSecAuthorization Authorization,
		ICFSecTableInfo rec )
	{
		final String S_ProcName = "deleteTableInfo";
		boolean permissionGranted = canDeleteTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletetableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		if (rec == null) {
			return;
		}
		if (rec instanceof CFSecJpaTableInfo) {
			CFSecJpaTableInfo jparec = (CFSecJpaTableInfo)rec;
			schema.getJpaHooksSchema().getTableInfoService().deleteByIdIdx(jparec.getPKey());
		}
		else {
			throw new CFLibUnsupportedClassException(getClass(), "deleteTableInfo", "rec", rec, "CFSecJpaTableInfo");
		}

		throw new CFLibNotImplementedYetException(getClass(), "deleteTableInfo");
	}

	/**
	 *	Delete the TableInfo instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The primary key identifying the instance to be deleted.
	 */
	@Override
	public void deleteTableInfoByIdIdx( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ argKey )
	{
		final String S_ProcName = "deleteTableInfoByIdIdx";
		boolean permissionGranted = canDeleteTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletetableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getTableInfoService().deleteByIdIdx(argKey);
	}

	/**
	 *	Delete the TableInfo instances identified by the key TableNameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	TableName	The TableInfo key attribute of the instance generating the id.
	 */
	@Override
	public void deleteTableInfoByTableNameIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argTableName )
	{
		final String S_ProcName = "deleteTableInfoByTableNameIdx";
		boolean permissionGranted = canDeleteTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletetableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getTableInfoService().deleteByTableNameIdx(argTableName);
	}


	/**
	 *	Delete the TableInfo instances identified by the key TableNameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteTableInfoByTableNameIdx( ICFSecAuthorization Authorization,
		ICFSecTableInfoByTableNameIdxKey argKey )
	{
		final String S_ProcName = "deleteTableInfoByTableNameIdx";
		boolean permissionGranted = canDeleteTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletetableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getTableInfoService().deleteByTableNameIdx(argKey.getRequiredTableName());
	}

	/**
	 *	Delete the TableInfo instances identified by the key SuperNameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SuperName	The TableInfo key attribute of the instance generating the id.
	 */
	@Override
	public void deleteTableInfoBySuperNameIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSuperName )
	{
		final String S_ProcName = "deleteTableInfoBySuperNameIdx";
		boolean permissionGranted = canDeleteTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletetableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getTableInfoService().deleteBySuperNameIdx(argSuperName);
	}


	/**
	 *	Delete the TableInfo instances identified by the key SuperNameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteTableInfoBySuperNameIdx( ICFSecAuthorization Authorization,
		ICFSecTableInfoBySuperNameIdxKey argKey )
	{
		final String S_ProcName = "deleteTableInfoBySuperNameIdx";
		boolean permissionGranted = canDeleteTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletetableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getTableInfoService().deleteBySuperNameIdx(argKey.getOptionalSuperName());
	}

	/**
	 *	Delete the TableInfo instances identified by the key SchemaNameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SchemaName	The TableInfo key attribute of the instance generating the id.
	 */
	@Override
	public void deleteTableInfoBySchemaNameIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSchemaName )
	{
		final String S_ProcName = "deleteTableInfoBySchemaNameIdx";
		boolean permissionGranted = canDeleteTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletetableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getTableInfoService().deleteBySchemaNameIdx(argSchemaName);
	}


	/**
	 *	Delete the TableInfo instances identified by the key SchemaNameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteTableInfoBySchemaNameIdx( ICFSecAuthorization Authorization,
		ICFSecTableInfoBySchemaNameIdxKey argKey )
	{
		final String S_ProcName = "deleteTableInfoBySchemaNameIdx";
		boolean permissionGranted = canDeleteTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletetableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getTableInfoService().deleteBySchemaNameIdx(argKey.getRequiredSchemaName());
	}

	/**
	 *	Delete the TableInfo instances identified by the key SchemaBkCodeIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SchemaName	The TableInfo key attribute of the instance generating the id.
	 *
	 *	@param	BackingClassCode	The TableInfo key attribute of the instance generating the id.
	 */
	@Override
	public void deleteTableInfoBySchemaBkCodeIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSchemaName,
		$implIJavaAtomType$ argBackingClassCode )
	{
		final String S_ProcName = "deleteTableInfoBySchemaBkCodeIdx";
		boolean permissionGranted = canDeleteTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletetableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getTableInfoService().deleteBySchemaBkCodeIdx(argSchemaName,
		argBackingClassCode);
	}


	/**
	 *	Delete the TableInfo instances identified by the key SchemaBkCodeIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteTableInfoBySchemaBkCodeIdx( ICFSecAuthorization Authorization,
		ICFSecTableInfoBySchemaBkCodeIdxKey argKey )
	{
		final String S_ProcName = "deleteTableInfoBySchemaBkCodeIdx";
		boolean permissionGranted = canDeleteTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletetableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getTableInfoService().deleteBySchemaBkCodeIdx(argKey.getRequiredSchemaName(),
			argKey.getRequiredBackingClassCode());
	}

	/**
	 *	Delete the TableInfo instances identified by the key SchemaRTCodeIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	RuntimeClassCode	The TableInfo key attribute of the instance generating the id.
	 */
	@Override
	public void deleteTableInfoBySchemaRTCodeIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argRuntimeClassCode )
	{
		final String S_ProcName = "deleteTableInfoBySchemaRTCodeIdx";
		boolean permissionGranted = canDeleteTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletetableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getTableInfoService().deleteBySchemaRTCodeIdx(argRuntimeClassCode);
	}


	/**
	 *	Delete the TableInfo instances identified by the key SchemaRTCodeIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	argKey	The key identifying the instances to be deleted.
	 */
	@Override
	public void deleteTableInfoBySchemaRTCodeIdx( ICFSecAuthorization Authorization,
		ICFSecTableInfoBySchemaRTCodeIdxKey argKey )
	{
		final String S_ProcName = "deleteTableInfoBySchemaRTCodeIdx";
		boolean permissionGranted = canDeleteTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "deletetableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		schema.getJpaHooksSchema().getTableInfoService().deleteBySchemaRTCodeIdx(argKey.getRequiredRuntimeClassCode());
	}


	/**
	 *	Read the derived TableInfo record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the TableInfo instance to be read.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecTableInfo readDerived( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ PKey )
	{
		final String S_ProcName = "readDerived";
		boolean permissionGranted = canReadTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readtableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecTableInfo retval = schema.getJpaHooksSchema().getTableInfoService().find(PKey);
		return(retval);
	}

	/**
	 *	Lock the derived TableInfo record instance by primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the TableInfo instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecTableInfo lockDerived( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ PKey )
	{
		final String S_ProcName = "lockDerived";
		boolean permissionGranted = canUpdateTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatetableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		ICFSecTableInfo retval = schema.getJpaHooksSchema().getTableInfoService().lockByIdIdx(PKey);
		return(retval);
	}

	/**
	 *	Read all TableInfo instances.
	 *
	 *	@param	Authorization	The session authorization information.	
	 *
	 *	@return An array of derived record instances, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecTableInfo[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "readAllDerived";
		boolean permissionGranted = canReadTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readtableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		List<CFSecJpaTableInfo> retlist = schema.getJpaHooksSchema().getTableInfoService().findAll();
		ICFSecTableInfo[] retset = new ICFSecTableInfo[retlist.size()];
		int idx = 0;
		for (CFSecJpaTableInfo cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read the derived TableInfo record instance identified by the unique key IdIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	TableInfoId	The TableInfo key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecTableInfo readDerivedByIdIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argTableInfoId )
	{
		final String S_ProcName = "readDerivedByIdIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadTableInfo(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readtableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		ICFSecTableInfo retval = schema.getJpaHooksSchema().getTableInfoService().find(argTableInfoId);
		return(retval);
	}

	/**
	 *	Read the derived TableInfo record instance identified by the unique key TableNameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	TableName	The TableInfo key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecTableInfo readDerivedByTableNameIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argTableName )
	{
		final String S_ProcName = "readDerivedByTableNameIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadTableInfo(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readtableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		ICFSecTableInfo retval = schema.getJpaHooksSchema().getTableInfoService().findByTableNameIdx(argTableName);
		return(retval);
	}

	/**
	 *	Read an array of the derived TableInfo record instances identified by the duplicate key SuperNameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SuperName	The TableInfo key attribute of the instance generating the id.
	 *
	 *	@return An array of derived instances for the specified key, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecTableInfo[] readDerivedBySuperNameIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSuperName )
	{
		final String S_ProcName = "readDerivedBySuperNameIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadTableInfo(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readtableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		List<CFSecJpaTableInfo> retlist = schema.getJpaHooksSchema().getTableInfoService().findBySuperNameIdx(argSuperName);
		ICFSecTableInfo[] retset = new ICFSecTableInfo[retlist.size()];
		int idx = 0;
		for (CFSecJpaTableInfo cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read an array of the derived TableInfo record instances identified by the duplicate key SchemaNameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SchemaName	The TableInfo key attribute of the instance generating the id.
	 *
	 *	@return An array of derived instances for the specified key, potentially with 0 elements in the set.
	 */
	@Override
	public ICFSecTableInfo[] readDerivedBySchemaNameIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSchemaName )
	{
		final String S_ProcName = "readDerivedBySchemaNameIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadTableInfo(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readtableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		List<CFSecJpaTableInfo> retlist = schema.getJpaHooksSchema().getTableInfoService().findBySchemaNameIdx(argSchemaName);
		ICFSecTableInfo[] retset = new ICFSecTableInfo[retlist.size()];
		int idx = 0;
		for (CFSecJpaTableInfo cur: retlist) {
			retset[idx++] = cur;
		}
		return( retset );
	}

	/**
	 *	Read the derived TableInfo record instance identified by the unique key SchemaBkCodeIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SchemaName	The TableInfo key attribute of the instance generating the id.
	 *
	 *	@param	BackingClassCode	The TableInfo key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecTableInfo readDerivedBySchemaBkCodeIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSchemaName,
		$implIJavaAtomType$ argBackingClassCode )
	{
		final String S_ProcName = "readDerivedBySchemaBkCodeIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadTableInfo(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readtableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		ICFSecTableInfo retval = schema.getJpaHooksSchema().getTableInfoService().findBySchemaBkCodeIdx(argSchemaName,
		argBackingClassCode);
		return(retval);
	}

	/**
	 *	Read the derived TableInfo record instance identified by the unique key SchemaRTCodeIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	RuntimeClassCode	The TableInfo key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 */
	@Override
	public ICFSecTableInfo readDerivedBySchemaRTCodeIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argRuntimeClassCode )
	{
		final String S_ProcName = "readDerivedBySchemaRTCodeIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadTableInfo(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readtableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		ICFSecTableInfo retval = schema.getJpaHooksSchema().getTableInfoService().findBySchemaRTCodeIdx(argRuntimeClassCode);
		return(retval);
	}

	/**
	 *	Read the specific TableInfo record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the TableInfo instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecTableInfo readRec( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ PKey )
	{
		final String S_ProcName = "readRec";
		boolean permissionGranted = canReadTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readtableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readRec");
	}

	/**
	 *	Lock the specific TableInfo record instance identified by the primary key.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PKey	The primary key of the TableInfo instance to be locked.
	 *
	 *	@return The record instance for the specified primary key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecTableInfo lockRec( ICFSecAuthorization Authorization,
		$iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$ PKey )
	{
		final String S_ProcName = "lockRec";
		boolean permissionGranted = canUpdateTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "updatetableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "lockRec");
	}

	/**
	 *	Read all the specific TableInfo record instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific TableInfo instances in the database accessible for the Authorization.
	 */
	@Override
	public ICFSecTableInfo[] readAllRec( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "readAllRec";
		boolean permissionGranted = canReadTableInfo(S_ProcName, Authorization);
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readtableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}

		throw new CFLibNotImplementedYetException(getClass(), "readAllRec");
	}


	/**
	 *	Read the specific TableInfo record instance identified by the unique key IdIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	TableInfoId	The TableInfo key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecTableInfo readRecByIdIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argTableInfoId )
	{
		final String S_ProcName = "readRecByIdIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadTableInfo(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readtableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecByIdIdx");
	}

	/**
	 *	Read the specific TableInfo record instance identified by the unique key TableNameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	TableName	The TableInfo key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecTableInfo readRecByTableNameIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argTableName )
	{
		final String S_ProcName = "readRecByTableNameIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadTableInfo(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readtableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecByTableNameIdx");
	}

	/**
	 *	Read an array of the specific TableInfo record instances identified by the duplicate key SuperNameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SuperName	The TableInfo key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecTableInfo[] readRecBySuperNameIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSuperName )
	{
		final String S_ProcName = "readRecBySuperNameIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadTableInfo(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readtableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecBySuperNameIdx");
	}

	/**
	 *	Read an array of the specific TableInfo record instances identified by the duplicate key SchemaNameIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SchemaName	The TableInfo key attribute of the instance generating the id.
	 *
	 *	@return An array of derived record instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecTableInfo[] readRecBySchemaNameIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSchemaName )
	{
		final String S_ProcName = "readRecBySchemaNameIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadTableInfo(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readtableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecBySchemaNameIdx");
	}

	/**
	 *	Read the specific TableInfo record instance identified by the unique key SchemaBkCodeIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	SchemaName	The TableInfo key attribute of the instance generating the id.
	 *
	 *	@param	BackingClassCode	The TableInfo key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecTableInfo readRecBySchemaBkCodeIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argSchemaName,
		$implIJavaAtomType$ argBackingClassCode )
	{
		final String S_ProcName = "readRecBySchemaBkCodeIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadTableInfo(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readtableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecBySchemaBkCodeIdx");
	}

	/**
	 *	Read the specific TableInfo record instance identified by the unique key SchemaRTCodeIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	RuntimeClassCode	The TableInfo key attribute of the instance generating the id.
	 *
	 *	@return The record instance for the specified key, or null if there is
	 *		no such existing key value.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	@Override
	public ICFSecTableInfo readRecBySchemaRTCodeIdx( ICFSecAuthorization Authorization,
		$implIJavaAtomType$ argRuntimeClassCode )
	{
		final String S_ProcName = "readRecBySchemaRTCodeIdx";
		boolean permissionGranted = false;
		if (!permissionGranted) {
			permissionGranted = canReadTableInfo(S_ProcName, Authorization);
		}
		if (!permissionGranted) {
			throw new CFLibPermissionDeniedException(getClass(), S_ProcName, "readtableinfo", ICFSecSchema.SCHEMA_NAME, ICFSecTableInfoTable.TABLE_NAME, Authorization.getAuthUuid6().toString());//"Permission '%4$s' denied attempting to access %1$s.%2$s for user id %3$s"
		}
		throw new CFLibNotImplementedYetException(getClass(), "readRecBySchemaRTCodeIdx");
	}
}
