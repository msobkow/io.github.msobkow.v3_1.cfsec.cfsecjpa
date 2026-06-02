// Description: Java 25 Spring JPA Repository for SecClusRole

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
 *	JpaRepository for the CFSecJpaSecClusRole entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa.
 *	The manufactured repositories try to provide a rich, do-it-all interface to the JPA data store, with both object and argument-based implementations of the interface defined.
 */
@Transactional(readOnly = true)
public interface CFSecJpaSecClusRoleRepository extends JpaRepository<CFSecJpaSecClusRole, CFLibDbKeyHash256> {

	@Transactional
	@Modifying
	CFSecJpaSecClusRole save(CFSecJpaSecClusRole obj);

	/**
	 *	Argument-based get database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredSecClusRoleId
	 *
	 *		@return The retrieved entity, usually from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaSecClusRole r where r.requiredSecClusRoleId = :secClusRoleId")
	CFSecJpaSecClusRole get(@Param("secClusRoleId") CFLibDbKeyHash256 requiredSecClusRoleId);

	// CFSecJpaSecClusRole specified index readers

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecSecClusRoleByClusterIdxKey as arguments.
	 *
	 *		@param requiredClusterId
	 *
	 *		@return List&lt;CFSecJpaSecClusRole&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaSecClusRole r where r.requiredOwnerCluster.requiredId = :clusterId")
	List<CFSecJpaSecClusRole> findByClusterIdx(@Param("clusterId") CFLibDbKeyHash256 requiredClusterId);

	/**
	 *	CFSecSecClusRoleByClusterIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecClusRoleByClusterIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaSecClusRole> findByClusterIdx(ICFSecSecClusRoleByClusterIdxKey key) {
		return( findByClusterIdx(key.getRequiredClusterId()));
	}

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecSecClusRoleByNameIdxKey as arguments.
	 *
	 *		@param requiredName
	 *
	 *		@return List&lt;CFSecJpaSecClusRole&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaSecClusRole r where r.requiredContainerSysRole.requiredName = :name")
	List<CFSecJpaSecClusRole> findByNameIdx(@Param("name") String requiredName);

	/**
	 *	CFSecSecClusRoleByNameIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecClusRoleByNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaSecClusRole> findByNameIdx(ICFSecSecClusRoleByNameIdxKey key) {
		return( findByNameIdx(key.getRequiredName()));
	}

	/**
	 *	Read an entity using the columns of the CFSecSecClusRoleByUNameIdxKey as arguments.
	 *
	 *		@param requiredClusterId
	 *		@param requiredName
	 *
	 *		@return The found entity, typically from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaSecClusRole r where r.requiredOwnerCluster.requiredId = :clusterId and r.requiredContainerSysRole.requiredName = :name")
	CFSecJpaSecClusRole findByUNameIdx(@Param("clusterId") CFLibDbKeyHash256 requiredClusterId,
		@Param("name") String requiredName);

	/**
	 *	CFSecSecClusRoleByUNameIdxKey entity reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecClusRoleByUNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity, typically from the JPA cache, or null if no such entity exists.
	 */
	default CFSecJpaSecClusRole findByUNameIdx(ICFSecSecClusRoleByUNameIdxKey key) {
		return( findByUNameIdx(key.getRequiredClusterId(), key.getRequiredName()));
	}

	// CFSecJpaSecClusRole specified delete-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecClusRoleId
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecClusRole r where r.requiredSecClusRoleId = :secClusRoleId")
	CFSecJpaSecClusRole lockByIdIdx(@Param("secClusRoleId") CFLibDbKeyHash256 requiredSecClusRoleId);

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredClusterId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecClusRole r where r.requiredOwnerCluster.requiredId = :clusterId")
	List<CFSecJpaSecClusRole> lockByClusterIdx(@Param("clusterId") CFLibDbKeyHash256 requiredClusterId);

	/**
	 *	CFSecSecClusRoleByClusterIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaSecClusRole> lockByClusterIdx(ICFSecSecClusRoleByClusterIdxKey key) {
		return( lockByClusterIdx(key.getRequiredClusterId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredName
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecClusRole r where r.requiredContainerSysRole.requiredName = :name")
	List<CFSecJpaSecClusRole> lockByNameIdx(@Param("name") String requiredName);

	/**
	 *	CFSecSecClusRoleByNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaSecClusRole> lockByNameIdx(ICFSecSecClusRoleByNameIdxKey key) {
		return( lockByNameIdx(key.getRequiredName()));
	}

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredClusterId
	 *		@param requiredName
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecClusRole r where r.requiredOwnerCluster.requiredId = :clusterId and r.requiredContainerSysRole.requiredName = :name")
	CFSecJpaSecClusRole lockByUNameIdx(@Param("clusterId") CFLibDbKeyHash256 requiredClusterId,
		@Param("name") String requiredName);

	/**
	 *	CFSecSecClusRoleByUNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	default CFSecJpaSecClusRole lockByUNameIdx(ICFSecSecClusRoleByUNameIdxKey key) {
		return( lockByUNameIdx(key.getRequiredClusterId(), key.getRequiredName()));
	}

	// CFSecJpaSecClusRole specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecClusRoleId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecClusRole r where r.requiredSecClusRoleId = :secClusRoleId")
	void deleteByIdIdx(@Param("secClusRoleId") CFLibDbKeyHash256 requiredSecClusRoleId);

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredClusterId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecClusRole r where r.requiredOwnerCluster.requiredId = :clusterId")
	void deleteByClusterIdx(@Param("clusterId") CFLibDbKeyHash256 requiredClusterId);

	/**
	 *	CFSecSecClusRoleByClusterIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecClusRoleByClusterIdxKey of the entity to be locked.
	 */
	default void deleteByClusterIdx(ICFSecSecClusRoleByClusterIdxKey key) {
		deleteByClusterIdx(key.getRequiredClusterId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredName
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecClusRole r where r.requiredContainerSysRole.requiredName = :name")
	void deleteByNameIdx(@Param("name") String requiredName);

	/**
	 *	CFSecSecClusRoleByNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecClusRoleByNameIdxKey of the entity to be locked.
	 */
	default void deleteByNameIdx(ICFSecSecClusRoleByNameIdxKey key) {
		deleteByNameIdx(key.getRequiredName());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredClusterId
	 *		@param requiredName
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecClusRole r where r.requiredOwnerCluster.requiredId = :clusterId and r.requiredContainerSysRole.requiredName = :name")
	void deleteByUNameIdx(@Param("clusterId") CFLibDbKeyHash256 requiredClusterId,
		@Param("name") String requiredName);

	/**
	 *	CFSecSecClusRoleByUNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecClusRoleByUNameIdxKey of the entity to be locked.
	 */
	default void deleteByUNameIdx(ICFSecSecClusRoleByUNameIdxKey key) {
		deleteByUNameIdx(key.getRequiredClusterId(), key.getRequiredName());
	}

}
