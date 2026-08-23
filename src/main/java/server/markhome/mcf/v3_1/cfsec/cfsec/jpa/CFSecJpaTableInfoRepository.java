// Description: Java 25 Spring JPA Repository for TableInfo

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

import java.io.Serializable;
import java.math.*;
import java.time.*;
import java.util.*;
import jakarta.persistence.*;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.keyhash.*;
import server.markhome.mcf.v3_1.cflib.xml.CFLibXmlUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.transaction.annotation.Transactional;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/**
 *	JpaRepository for the CFSecJpaTableInfo entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa.
 *	The manufactured repositories try to provide a rich, do-it-all interface to the JPA data store, with both object and argument-based implementations of the interface defined.
 */
@Transactional(readOnly = true)
public interface CFSecJpaTableInfoRepository extends JpaRepository<CFSecJpaTableInfo, Integer> {

	@Transactional
	@Modifying
	CFSecJpaTableInfo save(CFSecJpaTableInfo obj);

	/**
	 *	Argument-based get database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredTableInfoId
	 *
	 *		@return The retrieved entity, usually from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaTableInfo r where r.requiredTableInfoId = :tableInfoId")
	CFSecJpaTableInfo get(@Param("tableInfoId") int requiredTableInfoId);

	// CFSecJpaTableInfo specified index readers

	/**
	 *	Read an entity using the columns of the CFSecTableInfoByTableNameIdxKey as arguments.
	 *
	 *		@param requiredTableName
	 *
	 *		@return The found entity, typically from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaTableInfo r where r.requiredTableName = :tableName")
	CFSecJpaTableInfo findByTableNameIdx(@Param("tableName") String requiredTableName);

	/**
	 *	CFSecTableInfoByTableNameIdxKey entity reader convenience method for object-based access.
	 *
	 *		@param key The CFSecTableInfoByTableNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity, typically from the JPA cache, or null if no such entity exists.
	 */
	default CFSecJpaTableInfo findByTableNameIdx(ICFSecTableInfoByTableNameIdxKey key) {
		return( findByTableNameIdx(key.getRequiredTableName()));
	}

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecTableInfoBySuperNameIdxKey as arguments.
	 *
	 *		@param optionalSuperName
	 *
	 *		@return List&lt;CFSecJpaTableInfo&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaTableInfo r where r.optionalParentSuperRef.requiredTableName = :superName")
	List<CFSecJpaTableInfo> findBySuperNameIdx(@Param("superName") String optionalSuperName);

	/**
	 *	CFSecTableInfoBySuperNameIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecTableInfoBySuperNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaTableInfo> findBySuperNameIdx(ICFSecTableInfoBySuperNameIdxKey key) {
		return( findBySuperNameIdx(key.getOptionalSuperName()));
	}

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecTableInfoBySchemaNameIdxKey as arguments.
	 *
	 *		@param requiredSchemaName
	 *
	 *		@return List&lt;CFSecJpaTableInfo&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaTableInfo r where r.requiredSchemaName = :schemaName")
	List<CFSecJpaTableInfo> findBySchemaNameIdx(@Param("schemaName") String requiredSchemaName);

	/**
	 *	CFSecTableInfoBySchemaNameIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecTableInfoBySchemaNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaTableInfo> findBySchemaNameIdx(ICFSecTableInfoBySchemaNameIdxKey key) {
		return( findBySchemaNameIdx(key.getRequiredSchemaName()));
	}

	/**
	 *	Read an entity using the columns of the CFSecTableInfoBySchemaBkCodeIdxKey as arguments.
	 *
	 *		@param requiredSchemaName
	 *		@param requiredBackingClassCode
	 *
	 *		@return The found entity, typically from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaTableInfo r where r.requiredSchemaName = :schemaName and r.requiredBackingClassCode = :backingClassCode")
	CFSecJpaTableInfo findBySchemaBkCodeIdx(@Param("schemaName") String requiredSchemaName,
		@Param("backingClassCode") int requiredBackingClassCode);

	/**
	 *	CFSecTableInfoBySchemaBkCodeIdxKey entity reader convenience method for object-based access.
	 *
	 *		@param key The CFSecTableInfoBySchemaBkCodeIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity, typically from the JPA cache, or null if no such entity exists.
	 */
	default CFSecJpaTableInfo findBySchemaBkCodeIdx(ICFSecTableInfoBySchemaBkCodeIdxKey key) {
		return( findBySchemaBkCodeIdx(key.getRequiredSchemaName(), key.getRequiredBackingClassCode()));
	}

	/**
	 *	Read an entity using the columns of the CFSecTableInfoBySchemaRTCodeIdxKey as arguments.
	 *
	 *		@param requiredRuntimeClassCode
	 *
	 *		@return The found entity, typically from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaTableInfo r where r.requiredRuntimeClassCode = :runtimeClassCode")
	CFSecJpaTableInfo findBySchemaRTCodeIdx(@Param("runtimeClassCode") int requiredRuntimeClassCode);

	/**
	 *	CFSecTableInfoBySchemaRTCodeIdxKey entity reader convenience method for object-based access.
	 *
	 *		@param key The CFSecTableInfoBySchemaRTCodeIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity, typically from the JPA cache, or null if no such entity exists.
	 */
	default CFSecJpaTableInfo findBySchemaRTCodeIdx(ICFSecTableInfoBySchemaRTCodeIdxKey key) {
		return( findBySchemaRTCodeIdx(key.getRequiredRuntimeClassCode()));
	}

	// CFSecJpaTableInfo specified delete-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredTableInfoId
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaTableInfo r where r.requiredTableInfoId = :tableInfoId")
	CFSecJpaTableInfo lockByIdIdx(@Param("tableInfoId") int requiredTableInfoId);

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredTableName
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaTableInfo r where r.requiredTableName = :tableName")
	CFSecJpaTableInfo lockByTableNameIdx(@Param("tableName") String requiredTableName);

	/**
	 *	CFSecTableInfoByTableNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	default CFSecJpaTableInfo lockByTableNameIdx(ICFSecTableInfoByTableNameIdxKey key) {
		return( lockByTableNameIdx(key.getRequiredTableName()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param optionalSuperName
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaTableInfo r where r.optionalParentSuperRef.requiredTableName = :superName")
	List<CFSecJpaTableInfo> lockBySuperNameIdx(@Param("superName") String optionalSuperName);

	/**
	 *	CFSecTableInfoBySuperNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaTableInfo> lockBySuperNameIdx(ICFSecTableInfoBySuperNameIdxKey key) {
		return( lockBySuperNameIdx(key.getOptionalSuperName()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSchemaName
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaTableInfo r where r.requiredSchemaName = :schemaName")
	List<CFSecJpaTableInfo> lockBySchemaNameIdx(@Param("schemaName") String requiredSchemaName);

	/**
	 *	CFSecTableInfoBySchemaNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaTableInfo> lockBySchemaNameIdx(ICFSecTableInfoBySchemaNameIdxKey key) {
		return( lockBySchemaNameIdx(key.getRequiredSchemaName()));
	}

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSchemaName
	 *		@param requiredBackingClassCode
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaTableInfo r where r.requiredSchemaName = :schemaName and r.requiredBackingClassCode = :backingClassCode")
	CFSecJpaTableInfo lockBySchemaBkCodeIdx(@Param("schemaName") String requiredSchemaName,
		@Param("backingClassCode") int requiredBackingClassCode);

	/**
	 *	CFSecTableInfoBySchemaBkCodeIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	default CFSecJpaTableInfo lockBySchemaBkCodeIdx(ICFSecTableInfoBySchemaBkCodeIdxKey key) {
		return( lockBySchemaBkCodeIdx(key.getRequiredSchemaName(), key.getRequiredBackingClassCode()));
	}

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredRuntimeClassCode
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaTableInfo r where r.requiredRuntimeClassCode = :runtimeClassCode")
	CFSecJpaTableInfo lockBySchemaRTCodeIdx(@Param("runtimeClassCode") int requiredRuntimeClassCode);

	/**
	 *	CFSecTableInfoBySchemaRTCodeIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	default CFSecJpaTableInfo lockBySchemaRTCodeIdx(ICFSecTableInfoBySchemaRTCodeIdxKey key) {
		return( lockBySchemaRTCodeIdx(key.getRequiredRuntimeClassCode()));
	}

	// CFSecJpaTableInfo specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredTableInfoId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaTableInfo r where r.requiredTableInfoId = :tableInfoId")
	void deleteByIdIdx(@Param("tableInfoId") int requiredTableInfoId);

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredTableName
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaTableInfo r where r.requiredTableName = :tableName")
	void deleteByTableNameIdx(@Param("tableName") String requiredTableName);

	/**
	 *	CFSecTableInfoByTableNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecTableInfoByTableNameIdxKey of the entity to be locked.
	 */
	default void deleteByTableNameIdx(ICFSecTableInfoByTableNameIdxKey key) {
		deleteByTableNameIdx(key.getRequiredTableName());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param optionalSuperName
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaTableInfo r where r.optionalParentSuperRef.requiredTableName = :superName")
	void deleteBySuperNameIdx(@Param("superName") String optionalSuperName);

	/**
	 *	CFSecTableInfoBySuperNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecTableInfoBySuperNameIdxKey of the entity to be locked.
	 */
	default void deleteBySuperNameIdx(ICFSecTableInfoBySuperNameIdxKey key) {
		deleteBySuperNameIdx(key.getOptionalSuperName());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSchemaName
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaTableInfo r where r.requiredSchemaName = :schemaName")
	void deleteBySchemaNameIdx(@Param("schemaName") String requiredSchemaName);

	/**
	 *	CFSecTableInfoBySchemaNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecTableInfoBySchemaNameIdxKey of the entity to be locked.
	 */
	default void deleteBySchemaNameIdx(ICFSecTableInfoBySchemaNameIdxKey key) {
		deleteBySchemaNameIdx(key.getRequiredSchemaName());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSchemaName
	 *		@param requiredBackingClassCode
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaTableInfo r where r.requiredSchemaName = :schemaName and r.requiredBackingClassCode = :backingClassCode")
	void deleteBySchemaBkCodeIdx(@Param("schemaName") String requiredSchemaName,
		@Param("backingClassCode") int requiredBackingClassCode);

	/**
	 *	CFSecTableInfoBySchemaBkCodeIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecTableInfoBySchemaBkCodeIdxKey of the entity to be locked.
	 */
	default void deleteBySchemaBkCodeIdx(ICFSecTableInfoBySchemaBkCodeIdxKey key) {
		deleteBySchemaBkCodeIdx(key.getRequiredSchemaName(), key.getRequiredBackingClassCode());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredRuntimeClassCode
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaTableInfo r where r.requiredRuntimeClassCode = :runtimeClassCode")
	void deleteBySchemaRTCodeIdx(@Param("runtimeClassCode") int requiredRuntimeClassCode);

	/**
	 *	CFSecTableInfoBySchemaRTCodeIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecTableInfoBySchemaRTCodeIdxKey of the entity to be locked.
	 */
	default void deleteBySchemaRTCodeIdx(ICFSecTableInfoBySchemaRTCodeIdxKey key) {
		deleteBySchemaRTCodeIdx(key.getRequiredRuntimeClassCode());
	}

}
