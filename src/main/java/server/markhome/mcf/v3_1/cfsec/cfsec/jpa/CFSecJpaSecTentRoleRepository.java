// Description: Java 25 Spring JPA Repository for SecTentRole

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
 *	JpaRepository for the CFSecJpaSecTentRole entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa.
 *	The manufactured repositories try to provide a rich, do-it-all interface to the JPA data store, with both object and argument-based implementations of the interface defined.
 */
@Transactional(readOnly = true)
public interface CFSecJpaSecTentRoleRepository extends JpaRepository<CFSecJpaSecTentRole, $iterate Columns ( lone implIJavaOptAtomType first implIJavaOptAtomType each implCommaIJavaOptAtomType empty empty )$> {

	@Transactional
	@Modifying
	CFSecJpaSecTentRole save(CFSecJpaSecTentRole obj);

	/**
	 *	Argument-based get database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredSecTentRoleId
	 *
	 *		@return The retrieved entity, usually from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaSecTentRole r where r.requiredSecTentRoleId = :secTentRoleId")
	CFSecJpaSecTentRole get(@Param("secTentRoleId") $implIJavaAtomType$ requiredSecTentRoleId);

	// CFSecJpaSecTentRole specified index readers

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecSecTentRoleByTenantIdxKey as arguments.
	 *
	 *		@param requiredTenantId
	 *
	 *		@return List&lt;CFSecJpaSecTentRole&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaSecTentRole r where r.requiredOwnerTenant.requiredId = :tenantId")
	List<CFSecJpaSecTentRole> findByTenantIdx(@Param("tenantId") $implIJavaAtomType$ requiredTenantId);

	/**
	 *	CFSecSecTentRoleByTenantIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecTentRoleByTenantIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaSecTentRole> findByTenantIdx(ICFSecSecTentRoleByTenantIdxKey key) {
		return( findByTenantIdx(key.getRequiredTenantId()));
	}

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecSecTentRoleByNameIdxKey as arguments.
	 *
	 *		@param requiredName
	 *
	 *		@return List&lt;CFSecJpaSecTentRole&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaSecTentRole r where r.requiredContainerSysRole.requiredName = :name")
	List<CFSecJpaSecTentRole> findByNameIdx(@Param("name") $implIJavaAtomType$ requiredName);

	/**
	 *	CFSecSecTentRoleByNameIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecTentRoleByNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaSecTentRole> findByNameIdx(ICFSecSecTentRoleByNameIdxKey key) {
		return( findByNameIdx(key.getRequiredName()));
	}

	/**
	 *	Read an entity using the columns of the CFSecSecTentRoleByUNameIdxKey as arguments.
	 *
	 *		@param requiredTenantId
	 *		@param requiredName
	 *
	 *		@return The found entity, typically from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaSecTentRole r where r.requiredOwnerTenant.requiredId = :tenantId and r.requiredContainerSysRole.requiredName = :name")
	CFSecJpaSecTentRole findByUNameIdx(@Param("tenantId") $implIJavaAtomType$ requiredTenantId,
		@Param("name") $implIJavaAtomType$ requiredName);

	/**
	 *	CFSecSecTentRoleByUNameIdxKey entity reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecTentRoleByUNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity, typically from the JPA cache, or null if no such entity exists.
	 */
	default CFSecJpaSecTentRole findByUNameIdx(ICFSecSecTentRoleByUNameIdxKey key) {
		return( findByUNameIdx(key.getRequiredTenantId(), key.getRequiredName()));
	}

	// CFSecJpaSecTentRole specified delete-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecTentRoleId
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecTentRole r where r.requiredSecTentRoleId = :secTentRoleId")
	CFSecJpaSecTentRole lockByIdIdx(@Param("secTentRoleId") $implIJavaAtomType$ requiredSecTentRoleId);

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredTenantId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecTentRole r where r.requiredOwnerTenant.requiredId = :tenantId")
	List<CFSecJpaSecTentRole> lockByTenantIdx(@Param("tenantId") $implIJavaAtomType$ requiredTenantId);

	/**
	 *	CFSecSecTentRoleByTenantIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaSecTentRole> lockByTenantIdx(ICFSecSecTentRoleByTenantIdxKey key) {
		return( lockByTenantIdx(key.getRequiredTenantId()));
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
	@Query("select r from CFSecJpaSecTentRole r where r.requiredContainerSysRole.requiredName = :name")
	List<CFSecJpaSecTentRole> lockByNameIdx(@Param("name") $implIJavaAtomType$ requiredName);

	/**
	 *	CFSecSecTentRoleByNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaSecTentRole> lockByNameIdx(ICFSecSecTentRoleByNameIdxKey key) {
		return( lockByNameIdx(key.getRequiredName()));
	}

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredTenantId
	 *		@param requiredName
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecTentRole r where r.requiredOwnerTenant.requiredId = :tenantId and r.requiredContainerSysRole.requiredName = :name")
	CFSecJpaSecTentRole lockByUNameIdx(@Param("tenantId") $implIJavaAtomType$ requiredTenantId,
		@Param("name") $implIJavaAtomType$ requiredName);

	/**
	 *	CFSecSecTentRoleByUNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	default CFSecJpaSecTentRole lockByUNameIdx(ICFSecSecTentRoleByUNameIdxKey key) {
		return( lockByUNameIdx(key.getRequiredTenantId(), key.getRequiredName()));
	}

	// CFSecJpaSecTentRole specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecTentRoleId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecTentRole r where r.requiredSecTentRoleId = :secTentRoleId")
	void deleteByIdIdx(@Param("secTentRoleId") $implIJavaAtomType$ requiredSecTentRoleId);

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredTenantId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecTentRole r where r.requiredOwnerTenant.requiredId = :tenantId")
	void deleteByTenantIdx(@Param("tenantId") $implIJavaAtomType$ requiredTenantId);

	/**
	 *	CFSecSecTentRoleByTenantIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecTentRoleByTenantIdxKey of the entity to be locked.
	 */
	default void deleteByTenantIdx(ICFSecSecTentRoleByTenantIdxKey key) {
		deleteByTenantIdx(key.getRequiredTenantId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredName
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecTentRole r where r.requiredContainerSysRole.requiredName = :name")
	void deleteByNameIdx(@Param("name") $implIJavaAtomType$ requiredName);

	/**
	 *	CFSecSecTentRoleByNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecTentRoleByNameIdxKey of the entity to be locked.
	 */
	default void deleteByNameIdx(ICFSecSecTentRoleByNameIdxKey key) {
		deleteByNameIdx(key.getRequiredName());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredTenantId
	 *		@param requiredName
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecTentRole r where r.requiredOwnerTenant.requiredId = :tenantId and r.requiredContainerSysRole.requiredName = :name")
	void deleteByUNameIdx(@Param("tenantId") $implIJavaAtomType$ requiredTenantId,
		@Param("name") $implIJavaAtomType$ requiredName);

	/**
	 *	CFSecSecTentRoleByUNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecTentRoleByUNameIdxKey of the entity to be locked.
	 */
	default void deleteByUNameIdx(ICFSecSecTentRoleByUNameIdxKey key) {
		deleteByUNameIdx(key.getRequiredTenantId(), key.getRequiredName());
	}

}
