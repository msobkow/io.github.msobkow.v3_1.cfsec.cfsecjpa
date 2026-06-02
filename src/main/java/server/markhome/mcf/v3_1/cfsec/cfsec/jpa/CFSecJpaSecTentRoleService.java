// Description: Java 25 Spring JPA Service for SecTentRole

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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/**
 *	Service for the CFSecSecTentRole entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa
 *	using the CFSecSecTentRoleRepository to access them.
 */
@Service("cfsec31JpaSecTentRoleService")
public class CFSecJpaSecTentRoleService {

	@Autowired
	@Qualifier("cfsec31EntityManagerFactory")
	private LocalContainerEntityManagerFactoryBean cfsec31EntityManagerFactory;

	@Autowired
	private CFSecJpaSecTentRoleRepository cfsec31SecTentRoleRepository;

	/**
	 *	Create an entity, generating any database keys required along the way.
	 *
	 *		@param	data	The entity to be instantiated; must be a specific instance of CFSecJpaSecTentRole, not a subclass.
	 *
	 *		@return The updated/created entity.
	 */
	@Transactional(propagation = Propagation.REQUIRED,rollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRole create(CFSecJpaSecTentRole data) {
		final String S_ProcName = "create";
		if (data == null) {
			return( null );
		}
		CFLibDbKeyHash256 originalRequiredSecTentRoleId = data.getRequiredSecTentRoleId();
		boolean generatedRequiredSecTentRoleId = false;
		if (data.getRequiredOwnerTenant() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Owner",
				"Owner",
				"data.requiredOwnerTenant",
				"data.requiredOwnerTenant",
				"Tenant",
				"Tenant",
				null);
		}
		if (data.getRequiredContainerSysRole() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Container",
				"Container",
				"data.requiredContainerSysRole",
				"data.requiredContainerSysRole",
				"SecSysGrp",
				"SecSysGrp",
				null);
		}
		if(data.getRequiredTenantId() == null || data.getRequiredTenantId().isNull()) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredTenantId");
		}
		if(data.getRequiredName() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredName");
		}
		try {
			if(data.getPKey() != null && !data.getPKey().isNull() && cfsec31SecTentRoleRepository.existsById((CFLibDbKeyHash256)data.getPKey())) {
				return( (CFSecJpaSecTentRole)(cfsec31SecTentRoleRepository.findById((CFLibDbKeyHash256)(data.getPKey())).get()));
			}
			if (data.getRequiredRevision() <= 0) {
				data.setRequiredRevision(1);
			}
			if (data.getRequiredSecTentRoleId() == null || data.getRequiredSecTentRoleId().isNull()) {
				data.setRequiredSecTentRoleId(new CFLibDbKeyHash256(0));
				generatedRequiredSecTentRoleId = true;
			}
			LocalDateTime now = LocalDateTime.now();
			data.setCreatedAt(now);
			data.setUpdatedAt(now);
			return cfsec31SecTentRoleRepository.save(data);
		}
		catch(Exception ex) {
				if(generatedRequiredSecTentRoleId) {
					data.setRequiredSecTentRoleId(originalRequiredSecTentRoleId);
				}
			throw new CFLibDbException(getClass(),
				S_ProcName,
				ex);
		}
	}

	/**
	 *	Update an existing entity.
	 *
	 *		@param	data	The entity to be updated.
	 *
	 *		@return The updated entity.
	 */
	@Transactional(propagation = Propagation.REQUIRED,rollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRole update(CFSecJpaSecTentRole data) {
		final String S_ProcName = "update";
		if (data == null) {
			return( null );
		}
		if (data.getPKey() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.getPKey()");
		}
		if (data.getRequiredOwnerTenant() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Owner",
				"Owner",
				"data.requiredOwnerTenant",
				"data.requiredOwnerTenant",
				"Tenant",
				"Tenant",
				null);
		}
		if (data.getRequiredContainerSysRole() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Container",
				"Container",
				"data.requiredContainerSysRole",
				"data.requiredContainerSysRole",
				"SecSysGrp",
				"SecSysGrp",
				null);
		}
		if(data.getRequiredTenantId() == null || data.getRequiredTenantId().isNull()) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredTenantId");
		}
		if(data.getRequiredName() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredName");
		}
		// Ensure the entity exists and that the revision matches
		CFSecJpaSecTentRole existing = cfsec31SecTentRoleRepository.findById((CFLibDbKeyHash256)(data.getPKey()))
			.orElseThrow(() -> new CFLibCollisionDetectedException(getClass(), S_ProcName, data.getPKey()));
		if (existing.getRequiredRevision() != data.getRequiredRevision()) {
			throw new CFLibCollisionDetectedException(getClass(), S_ProcName, data.getPKey());
		}
		// Apply superior data relationships of CFSecSecTentRole to existing object
		existing.setRequiredOwnerTenant(data.getRequiredOwnerTenant());
		existing.setRequiredContainerSysRole(data.getRequiredContainerSysRole());
		// Apply data columns of CFSecSecTentRole to existing object
		// Update the audit columns
		data.setUpdatedAt(LocalDateTime.now());
		// Save the changes we've made
		return cfsec31SecTentRoleRepository.save(existing);
	}

	/**
	 *	Argument-based find database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredSecTentRoleId
	 *
	 *		@return The retrieved entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRole find(@Param("secTentRoleId") CFLibDbKeyHash256 requiredSecTentRoleId) {
		return( cfsec31SecTentRoleRepository.get(requiredSecTentRoleId));
	}

	/**
	 *	Retrieve all entities from the repository
	 *
	 *		@return The list of retrieved entities, which may be empty
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRole> findAll() {
		return( cfsec31SecTentRoleRepository.findAll() );
	}

	// CFSecSecTentRole specified index finders

	/**
	 *	Find zero or more entities into a List using the columns of the ICFSecSecTentRoleByTenantIdxKey as arguments.
	 *
	 *		@param requiredTenantId
	 *
	 *		@return List&lt;CFSecJpaSecTentRole&gt; of the found entities, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRole> findByTenantIdx(@Param("tenantId") CFLibDbKeyHash256 requiredTenantId) {
		return( cfsec31SecTentRoleRepository.findByTenantIdx(requiredTenantId));
	}

	/**
	 *	ICFSecSecTentRoleByTenantIdxKey entity list finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecSecTentRoleByTenantIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRole> findByTenantIdx(ICFSecSecTentRoleByTenantIdxKey key) {
		return( cfsec31SecTentRoleRepository.findByTenantIdx(key.getRequiredTenantId()));
	}

	/**
	 *	Find zero or more entities into a List using the columns of the ICFSecSecTentRoleByNameIdxKey as arguments.
	 *
	 *		@param requiredName
	 *
	 *		@return List&lt;CFSecJpaSecTentRole&gt; of the found entities, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRole> findByNameIdx(@Param("name") String requiredName) {
		return( cfsec31SecTentRoleRepository.findByNameIdx(requiredName));
	}

	/**
	 *	ICFSecSecTentRoleByNameIdxKey entity list finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecSecTentRoleByNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRole> findByNameIdx(ICFSecSecTentRoleByNameIdxKey key) {
		return( cfsec31SecTentRoleRepository.findByNameIdx(key.getRequiredName()));
	}

	/**
	 *	Find an entity using the columns of the ICFSecSecTentRoleByUNameIdxKey as arguments.
	 *
	 *		@param requiredTenantId
	 *		@param requiredName
	 *
	 *		@return The found entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRole findByUNameIdx(@Param("tenantId") CFLibDbKeyHash256 requiredTenantId,
		@Param("name") String requiredName) {
		return( cfsec31SecTentRoleRepository.findByUNameIdx(requiredTenantId,
			requiredName));
	}

	/**
	 *	ICFSecSecTentRoleByUNameIdxKey entity finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecSecTentRoleByUNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRole findByUNameIdx(ICFSecSecTentRoleByUNameIdxKey key) {
		return( cfsec31SecTentRoleRepository.findByUNameIdx(key.getRequiredTenantId(), key.getRequiredName()));
	}

	// CFSecSecTentRole specified lock-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecTentRoleId
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRole lockByIdIdx(@Param("secTentRoleId") CFLibDbKeyHash256 requiredSecTentRoleId) {
		return( cfsec31SecTentRoleRepository.lockByIdIdx(requiredSecTentRoleId));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredTenantId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRole> lockByTenantIdx(@Param("tenantId") CFLibDbKeyHash256 requiredTenantId) {
		return( cfsec31SecTentRoleRepository.lockByTenantIdx(requiredTenantId));
	}

	/**
	 *	ICFSecSecTentRoleByTenantIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRole> lockByTenantIdx(ICFSecSecTentRoleByTenantIdxKey key) {
		return( cfsec31SecTentRoleRepository.lockByTenantIdx(key.getRequiredTenantId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredName
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRole> lockByNameIdx(@Param("name") String requiredName) {
		return( cfsec31SecTentRoleRepository.lockByNameIdx(requiredName));
	}

	/**
	 *	ICFSecSecTentRoleByNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecTentRole> lockByNameIdx(ICFSecSecTentRoleByNameIdxKey key) {
		return( cfsec31SecTentRoleRepository.lockByNameIdx(key.getRequiredName()));
	}

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredTenantId
	 *		@param requiredName
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRole lockByUNameIdx(@Param("tenantId") CFLibDbKeyHash256 requiredTenantId,
		@Param("name") String requiredName) {
		return( cfsec31SecTentRoleRepository.lockByUNameIdx(requiredTenantId,
			requiredName));
	}

	/**
	 *	ICFSecSecTentRoleByUNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecTentRole lockByUNameIdx(ICFSecSecTentRoleByUNameIdxKey key) {
		return( cfsec31SecTentRoleRepository.lockByUNameIdx(key.getRequiredTenantId(), key.getRequiredName()));
	}

	// CFSecSecTentRole specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecTentRoleId
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByIdIdx(@Param("secTentRoleId") CFLibDbKeyHash256 requiredSecTentRoleId) {
		cfsec31SecTentRoleRepository.deleteByIdIdx(requiredSecTentRoleId);
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredTenantId
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByTenantIdx(@Param("tenantId") CFLibDbKeyHash256 requiredTenantId) {
		cfsec31SecTentRoleRepository.deleteByTenantIdx(requiredTenantId);
	}

	/**
	 *	ICFSecSecTentRoleByTenantIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecTentRoleByTenantIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByTenantIdx(ICFSecSecTentRoleByTenantIdxKey key) {
		cfsec31SecTentRoleRepository.deleteByTenantIdx(key.getRequiredTenantId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredName
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByNameIdx(@Param("name") String requiredName) {
		cfsec31SecTentRoleRepository.deleteByNameIdx(requiredName);
	}

	/**
	 *	ICFSecSecTentRoleByNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecTentRoleByNameIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByNameIdx(ICFSecSecTentRoleByNameIdxKey key) {
		cfsec31SecTentRoleRepository.deleteByNameIdx(key.getRequiredName());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredTenantId
	 *		@param requiredName
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByUNameIdx(@Param("tenantId") CFLibDbKeyHash256 requiredTenantId,
		@Param("name") String requiredName) {
		cfsec31SecTentRoleRepository.deleteByUNameIdx(requiredTenantId,
			requiredName);
	}

	/**
	 *	ICFSecSecTentRoleByUNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecTentRoleByUNameIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByUNameIdx(ICFSecSecTentRoleByUNameIdxKey key) {
		cfsec31SecTentRoleRepository.deleteByUNameIdx(key.getRequiredTenantId(), key.getRequiredName());
	}

}
