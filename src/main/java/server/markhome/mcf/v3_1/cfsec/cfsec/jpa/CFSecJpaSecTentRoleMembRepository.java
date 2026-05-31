// Description: Java 25 Spring JPA Repository for SecTentRoleMemb

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
 *	JpaRepository for the CFSecJpaSecTentRoleMemb entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa.
 *	The manufactured repositories try to provide a rich, do-it-all interface to the JPA data store, with both object and argument-based implementations of the interface defined.
 */
@Transactional(readOnly = true)
public interface CFSecJpaSecTentRoleMembRepository extends JpaRepository<CFSecJpaSecTentRoleMemb, CFSecJpaSecTentRoleMembPKey> {

	/**
	 *	Argument-based get database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredSecTentRoleId
	 *		@param requiredLoginId
	 *
	 *		@return The retrieved entity, usually from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaSecTentRoleMemb r where r.requiredContainerRole.requiredSecTentRoleId = :secTentRoleId and r.requiredParentUser.requiredLoginId = :loginId")
	CFSecJpaSecTentRoleMemb get(@Param("secTentRoleId") CFLibDbKeyHash256 requiredSecTentRoleId,
		@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecTentRoleMembPKey based read method for object-based access.
	 *
	 *		@param key The key of the entity to be read.
	 *
	 *		@return The entity read, usually from the JPA cache, or null if no such entity exists.
	 */
	default CFSecJpaSecTentRoleMemb get(ICFSecSecTentRoleMembPKey key) {
		return( get(key.getRequiredSecTentRoleId(), key.getRequiredLoginId()));
	}

	// CFSecJpaSecTentRoleMemb specified index readers

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecSecTentRoleMembByTentRoleIdxKey as arguments.
	 *
	 *		@param requiredSecTentRoleId
	 *
	 *		@return List&lt;CFSecJpaSecTentRoleMemb&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaSecTentRoleMemb r where r.requiredContainerRole.requiredSecTentRoleId = :secTentRoleId")
	List<CFSecJpaSecTentRoleMemb> findByTentRoleIdx(@Param("secTentRoleId") CFLibDbKeyHash256 requiredSecTentRoleId);

	/**
	 *	CFSecSecTentRoleMembByTentRoleIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecTentRoleMembByTentRoleIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaSecTentRoleMemb> findByTentRoleIdx(ICFSecSecTentRoleMembByTentRoleIdxKey key) {
		return( findByTentRoleIdx(key.getRequiredSecTentRoleId()));
	}

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecSecTentRoleMembByUserIdxKey as arguments.
	 *
	 *		@param requiredLoginId
	 *
	 *		@return List&lt;CFSecJpaSecTentRoleMemb&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaSecTentRoleMemb r where r.requiredParentUser.requiredLoginId = :loginId")
	List<CFSecJpaSecTentRoleMemb> findByUserIdx(@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecTentRoleMembByUserIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecTentRoleMembByUserIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaSecTentRoleMemb> findByUserIdx(ICFSecSecTentRoleMembByUserIdxKey key) {
		return( findByUserIdx(key.getRequiredLoginId()));
	}

	// CFSecJpaSecTentRoleMemb specified delete-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecTentRoleId
	 *		@param requiredLoginId
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecTentRoleMemb r where r.requiredContainerRole.requiredSecTentRoleId = :secTentRoleId and r.requiredParentUser.requiredLoginId = :loginId")
	CFSecJpaSecTentRoleMemb lockByIdIdx(@Param("secTentRoleId") CFLibDbKeyHash256 requiredSecTentRoleId,
		@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecTentRoleMembByIdIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	default CFSecJpaSecTentRoleMemb lockByIdIdx(ICFSecSecTentRoleMembPKey key) {
		return( lockByIdIdx(key.getRequiredSecTentRoleId(), key.getRequiredLoginId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecTentRoleId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecTentRoleMemb r where r.requiredContainerRole.requiredSecTentRoleId = :secTentRoleId")
	List<CFSecJpaSecTentRoleMemb> lockByTentRoleIdx(@Param("secTentRoleId") CFLibDbKeyHash256 requiredSecTentRoleId);

	/**
	 *	CFSecSecTentRoleMembByTentRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaSecTentRoleMemb> lockByTentRoleIdx(ICFSecSecTentRoleMembByTentRoleIdxKey key) {
		return( lockByTentRoleIdx(key.getRequiredSecTentRoleId()));
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
	@Query("select r from CFSecJpaSecTentRoleMemb r where r.requiredParentUser.requiredLoginId = :loginId")
	List<CFSecJpaSecTentRoleMemb> lockByUserIdx(@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecTentRoleMembByUserIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaSecTentRoleMemb> lockByUserIdx(ICFSecSecTentRoleMembByUserIdxKey key) {
		return( lockByUserIdx(key.getRequiredLoginId()));
	}

	// CFSecJpaSecTentRoleMemb specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecTentRoleId
	 *		@param requiredLoginId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecTentRoleMemb r where r.requiredContainerRole.requiredSecTentRoleId = :secTentRoleId and r.requiredParentUser.requiredLoginId = :loginId")
	void deleteByIdIdx(@Param("secTentRoleId") CFLibDbKeyHash256 requiredSecTentRoleId,
		@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecTentRoleMembByIdIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecTentRoleMembByIdIdxKey of the entity to be locked.
	 */
	default void deleteByIdIdx(ICFSecSecTentRoleMembPKey key) {
		deleteByIdIdx(key.getRequiredSecTentRoleId(), key.getRequiredLoginId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecTentRoleId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecTentRoleMemb r where r.requiredContainerRole.requiredSecTentRoleId = :secTentRoleId")
	void deleteByTentRoleIdx(@Param("secTentRoleId") CFLibDbKeyHash256 requiredSecTentRoleId);

	/**
	 *	CFSecSecTentRoleMembByTentRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecTentRoleMembByTentRoleIdxKey of the entity to be locked.
	 */
	default void deleteByTentRoleIdx(ICFSecSecTentRoleMembByTentRoleIdxKey key) {
		deleteByTentRoleIdx(key.getRequiredSecTentRoleId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredLoginId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecTentRoleMemb r where r.requiredParentUser.requiredLoginId = :loginId")
	void deleteByUserIdx(@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecTentRoleMembByUserIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecTentRoleMembByUserIdxKey of the entity to be locked.
	 */
	default void deleteByUserIdx(ICFSecSecTentRoleMembByUserIdxKey key) {
		deleteByUserIdx(key.getRequiredLoginId());
	}

}
