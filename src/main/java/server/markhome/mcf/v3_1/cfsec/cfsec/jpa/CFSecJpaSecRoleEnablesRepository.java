// Description: Java 25 Spring JPA Repository for SecRoleEnables

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
 *	JpaRepository for the CFSecJpaSecRoleEnables entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa.
 *	The manufactured repositories try to provide a rich, do-it-all interface to the JPA data store, with both object and argument-based implementations of the interface defined.
 */
@Transactional(readOnly = true)
public interface CFSecJpaSecRoleEnablesRepository extends JpaRepository<CFSecJpaSecRoleEnables, CFSecJpaSecRoleEnablesPKey> {

	/**
	 *	Argument-based get database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredSecRoleId
	 *		@param requiredEnableName
	 *
	 *		@return The retrieved entity, usually from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaSecRoleEnables r where r.pkey.requiredContainerRole.requiredSecRoleId = :secRoleId and r.pkey.requiredParentEnableGroup.requiredName = :enableName")
	CFSecJpaSecRoleEnables get(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId,
		@Param("enableName") String requiredEnableName);

	/**
	 *	CFSecSecRoleEnablesPKey based read method for object-based access.
	 *
	 *		@param key The key of the entity to be read.
	 *
	 *		@return The entity read, usually from the JPA cache, or null if no such entity exists.
	 */
	default CFSecJpaSecRoleEnables get(ICFSecSecRoleEnablesPKey key) {
		return( get(key.getRequiredSecRoleId(), key.getRequiredEnableName()));
	}

	// CFSecJpaSecRoleEnables specified index readers

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecSecRoleEnablesByRoleIdxKey as arguments.
	 *
	 *		@param requiredSecRoleId
	 *
	 *		@return List&lt;CFSecJpaSecRoleEnables&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaSecRoleEnables r where r.pkey.requiredContainerRole.requiredSecRoleId = :secRoleId")
	List<CFSecJpaSecRoleEnables> findByRoleIdx(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId);

	/**
	 *	CFSecSecRoleEnablesByRoleIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecRoleEnablesByRoleIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaSecRoleEnables> findByRoleIdx(ICFSecSecRoleEnablesByRoleIdxKey key) {
		return( findByRoleIdx(key.getRequiredSecRoleId()));
	}

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecSecRoleEnablesByNameIdxKey as arguments.
	 *
	 *		@param requiredEnableName
	 *
	 *		@return List&lt;CFSecJpaSecRoleEnables&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaSecRoleEnables r where r.pkey.requiredParentEnableGroup.requiredName = :enableName")
	List<CFSecJpaSecRoleEnables> findByNameIdx(@Param("enableName") String requiredEnableName);

	/**
	 *	CFSecSecRoleEnablesByNameIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecRoleEnablesByNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaSecRoleEnables> findByNameIdx(ICFSecSecRoleEnablesByNameIdxKey key) {
		return( findByNameIdx(key.getRequiredEnableName()));
	}

	// CFSecJpaSecRoleEnables specified delete-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecRoleId
	 *		@param requiredEnableName
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecRoleEnables r where r.pkey.requiredContainerRole.requiredSecRoleId = :secRoleId and r.pkey.requiredParentEnableGroup.requiredName = :enableName")
	CFSecJpaSecRoleEnables lockByIdIdx(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId,
		@Param("enableName") String requiredEnableName);

	/**
	 *	CFSecSecRoleEnablesByIdIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	default CFSecJpaSecRoleEnables lockByIdIdx(ICFSecSecRoleEnablesPKey key) {
		return( lockByIdIdx(key.getRequiredSecRoleId(), key.getRequiredEnableName()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecRoleId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecRoleEnables r where r.pkey.requiredContainerRole.requiredSecRoleId = :secRoleId")
	List<CFSecJpaSecRoleEnables> lockByRoleIdx(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId);

	/**
	 *	CFSecSecRoleEnablesByRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaSecRoleEnables> lockByRoleIdx(ICFSecSecRoleEnablesByRoleIdxKey key) {
		return( lockByRoleIdx(key.getRequiredSecRoleId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredEnableName
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecRoleEnables r where r.pkey.requiredParentEnableGroup.requiredName = :enableName")
	List<CFSecJpaSecRoleEnables> lockByNameIdx(@Param("enableName") String requiredEnableName);

	/**
	 *	CFSecSecRoleEnablesByNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaSecRoleEnables> lockByNameIdx(ICFSecSecRoleEnablesByNameIdxKey key) {
		return( lockByNameIdx(key.getRequiredEnableName()));
	}

	// CFSecJpaSecRoleEnables specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecRoleId
	 *		@param requiredEnableName
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecRoleEnables r where r.pkey.requiredContainerRole.requiredSecRoleId = :secRoleId and r.pkey.requiredParentEnableGroup.requiredName = :enableName")
	void deleteByIdIdx(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId,
		@Param("enableName") String requiredEnableName);

	/**
	 *	CFSecSecRoleEnablesByIdIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecRoleEnablesByIdIdxKey of the entity to be locked.
	 */
	default void deleteByIdIdx(ICFSecSecRoleEnablesPKey key) {
		deleteByIdIdx(key.getRequiredSecRoleId(), key.getRequiredEnableName());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecRoleId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecRoleEnables r where r.pkey.requiredContainerRole.requiredSecRoleId = :secRoleId")
	void deleteByRoleIdx(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId);

	/**
	 *	CFSecSecRoleEnablesByRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecRoleEnablesByRoleIdxKey of the entity to be locked.
	 */
	default void deleteByRoleIdx(ICFSecSecRoleEnablesByRoleIdxKey key) {
		deleteByRoleIdx(key.getRequiredSecRoleId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredEnableName
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecRoleEnables r where r.pkey.requiredParentEnableGroup.requiredName = :enableName")
	void deleteByNameIdx(@Param("enableName") String requiredEnableName);

	/**
	 *	CFSecSecRoleEnablesByNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecRoleEnablesByNameIdxKey of the entity to be locked.
	 */
	default void deleteByNameIdx(ICFSecSecRoleEnablesByNameIdxKey key) {
		deleteByNameIdx(key.getRequiredEnableName());
	}

}
