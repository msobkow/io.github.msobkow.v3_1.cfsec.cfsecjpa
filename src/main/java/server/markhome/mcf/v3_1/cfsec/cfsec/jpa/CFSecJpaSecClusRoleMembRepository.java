// Description: Java 25 Spring JPA Repository for SecClusRoleMemb

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
 *	JpaRepository for the CFSecJpaSecClusRoleMemb entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa.
 *	The manufactured repositories try to provide a rich, do-it-all interface to the JPA data store, with both object and argument-based implementations of the interface defined.
 */
@Transactional(readOnly = true)
public interface CFSecJpaSecClusRoleMembRepository extends JpaRepository<CFSecJpaSecClusRoleMemb, CFSecJpaSecClusRoleMembPKey> {

	/**
	 *	Argument-based get database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredSecClusRoleId
	 *		@param requiredLoginId
	 *
	 *		@return The retrieved entity, usually from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaSecClusRoleMemb r where r.pkey.requiredContainerRole.requiredSecClusRoleId = :secClusRoleId and r.pkey.requiredParentUser.requiredLoginId = :loginId")
	CFSecJpaSecClusRoleMemb get(@Param("secClusRoleId") CFLibDbKeyHash256 requiredSecClusRoleId,
		@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecClusRoleMembPKey based read method for object-based access.
	 *
	 *		@param key The key of the entity to be read.
	 *
	 *		@return The entity read, usually from the JPA cache, or null if no such entity exists.
	 */
	default CFSecJpaSecClusRoleMemb get(ICFSecSecClusRoleMembPKey key) {
		return( get(key.getRequiredSecClusRoleId(), key.getRequiredLoginId()));
	}

	// CFSecJpaSecClusRoleMemb specified index readers

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecSecClusRoleMembByClusRoleIdxKey as arguments.
	 *
	 *		@param requiredSecClusRoleId
	 *
	 *		@return List&lt;CFSecJpaSecClusRoleMemb&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaSecClusRoleMemb r where r.pkey.requiredContainerRole.requiredSecClusRoleId = :secClusRoleId")
	List<CFSecJpaSecClusRoleMemb> findByClusRoleIdx(@Param("secClusRoleId") CFLibDbKeyHash256 requiredSecClusRoleId);

	/**
	 *	CFSecSecClusRoleMembByClusRoleIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecClusRoleMembByClusRoleIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaSecClusRoleMemb> findByClusRoleIdx(ICFSecSecClusRoleMembByClusRoleIdxKey key) {
		return( findByClusRoleIdx(key.getRequiredSecClusRoleId()));
	}

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecSecClusRoleMembByLoginIdxKey as arguments.
	 *
	 *		@param requiredLoginId
	 *
	 *		@return List&lt;CFSecJpaSecClusRoleMemb&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaSecClusRoleMemb r where r.pkey.requiredParentUser.requiredLoginId = :loginId")
	List<CFSecJpaSecClusRoleMemb> findByLoginIdx(@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecClusRoleMembByLoginIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecClusRoleMembByLoginIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaSecClusRoleMemb> findByLoginIdx(ICFSecSecClusRoleMembByLoginIdxKey key) {
		return( findByLoginIdx(key.getRequiredLoginId()));
	}

	// CFSecJpaSecClusRoleMemb specified delete-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecClusRoleId
	 *		@param requiredLoginId
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecClusRoleMemb r where r.pkey.requiredContainerRole.requiredSecClusRoleId = :secClusRoleId and r.pkey.requiredParentUser.requiredLoginId = :loginId")
	CFSecJpaSecClusRoleMemb lockByIdIdx(@Param("secClusRoleId") CFLibDbKeyHash256 requiredSecClusRoleId,
		@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecClusRoleMembByIdIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	default CFSecJpaSecClusRoleMemb lockByIdIdx(ICFSecSecClusRoleMembPKey key) {
		return( lockByIdIdx(key.getRequiredSecClusRoleId(), key.getRequiredLoginId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecClusRoleId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecClusRoleMemb r where r.pkey.requiredContainerRole.requiredSecClusRoleId = :secClusRoleId")
	List<CFSecJpaSecClusRoleMemb> lockByClusRoleIdx(@Param("secClusRoleId") CFLibDbKeyHash256 requiredSecClusRoleId);

	/**
	 *	CFSecSecClusRoleMembByClusRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaSecClusRoleMemb> lockByClusRoleIdx(ICFSecSecClusRoleMembByClusRoleIdxKey key) {
		return( lockByClusRoleIdx(key.getRequiredSecClusRoleId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredLoginId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecClusRoleMemb r where r.pkey.requiredParentUser.requiredLoginId = :loginId")
	List<CFSecJpaSecClusRoleMemb> lockByLoginIdx(@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecClusRoleMembByLoginIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaSecClusRoleMemb> lockByLoginIdx(ICFSecSecClusRoleMembByLoginIdxKey key) {
		return( lockByLoginIdx(key.getRequiredLoginId()));
	}

	// CFSecJpaSecClusRoleMemb specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecClusRoleId
	 *		@param requiredLoginId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecClusRoleMemb r where r.pkey.requiredContainerRole.requiredSecClusRoleId = :secClusRoleId and r.pkey.requiredParentUser.requiredLoginId = :loginId")
	void deleteByIdIdx(@Param("secClusRoleId") CFLibDbKeyHash256 requiredSecClusRoleId,
		@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecClusRoleMembByIdIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecClusRoleMembByIdIdxKey of the entity to be locked.
	 */
	default void deleteByIdIdx(ICFSecSecClusRoleMembPKey key) {
		deleteByIdIdx(key.getRequiredSecClusRoleId(), key.getRequiredLoginId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecClusRoleId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecClusRoleMemb r where r.pkey.requiredContainerRole.requiredSecClusRoleId = :secClusRoleId")
	void deleteByClusRoleIdx(@Param("secClusRoleId") CFLibDbKeyHash256 requiredSecClusRoleId);

	/**
	 *	CFSecSecClusRoleMembByClusRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecClusRoleMembByClusRoleIdxKey of the entity to be locked.
	 */
	default void deleteByClusRoleIdx(ICFSecSecClusRoleMembByClusRoleIdxKey key) {
		deleteByClusRoleIdx(key.getRequiredSecClusRoleId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredLoginId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecClusRoleMemb r where r.pkey.requiredParentUser.requiredLoginId = :loginId")
	void deleteByLoginIdx(@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecClusRoleMembByLoginIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecClusRoleMembByLoginIdxKey of the entity to be locked.
	 */
	default void deleteByLoginIdx(ICFSecSecClusRoleMembByLoginIdxKey key) {
		deleteByLoginIdx(key.getRequiredLoginId());
	}

}
