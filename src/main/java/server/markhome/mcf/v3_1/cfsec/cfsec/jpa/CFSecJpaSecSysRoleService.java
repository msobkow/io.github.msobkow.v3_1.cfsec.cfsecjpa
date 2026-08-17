// Description: Java 25 Spring JPA Service for SecSysRole

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
 *	Service for the CFSecSecSysRole entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa
 *	using the CFSecSecSysRoleRepository to access them.
 */
@Service("cfsec31JpaSecSysRoleService")
public class CFSecJpaSecSysRoleService {

	@Autowired
	@Qualifier("cfsec31EntityManagerFactory")
	private LocalContainerEntityManagerFactoryBean cfsec31EntityManagerFactory;

	@Autowired
	private CFSecJpaSecSysRoleRepository cfsec31SecSysRoleRepository;

	/**
	 *	Create an entity, generating any database keys required along the way.
	 *
	 *		@param	data	The entity to be instantiated; must be a specific instance of CFSecJpaSecSysRole, not a subclass.
	 *
	 *		@return The updated/created entity.
	 */
	@Transactional(propagation = Propagation.REQUIRED,rollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRole create(CFSecJpaSecSysRole data) {
		final String S_ProcName = "create";
		if (data == null) {
			return( null );
		}
		ICFLibKeyHash256 originalRequiredSecSysRoleId = data.getRequiredSecSysRoleId();
		boolean generatedRequiredSecSysRoleId = false;
		if(data.getRequiredName() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredName");
		}
		try {
			if(data.getPKey() != null && !data.getPKey().isNull() && cfsec31SecSysRoleRepository.existsById((ICFLibKeyHash256)data.getPKey())) {
				return( (CFSecJpaSecSysRole)(cfsec31SecSysRoleRepository.findById((ICFLibKeyHash256)(data.getPKey())).get()));
			}
			if (data.getRequiredRevision() <= 0) {
				data.setRequiredRevision(1);
			}
			if (data.getRequiredSecSysRoleId() == null || data.getRequiredSecSysRoleId().isNull()) {
				data.setRequiredSecSysRoleId(new CFLibDbKeyHash256(0));
				generatedRequiredSecSysRoleId = true;
			}
			LocalDateTime now = LocalDateTime.now();
			data.setCreatedAt(now);
			data.setUpdatedAt(now);
			return cfsec31SecSysRoleRepository.save(data);
		}
		catch(Exception ex) {
				if(generatedRequiredSecSysRoleId) {
					data.setRequiredSecSysRoleId(originalRequiredSecSysRoleId);
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
	public CFSecJpaSecSysRole update(CFSecJpaSecSysRole data) {
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
		if(data.getRequiredName() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredName");
		}
		// Ensure the entity exists and that the revision matches
		CFSecJpaSecSysRole existing = cfsec31SecSysRoleRepository.findById((ICFLibKeyHash256)(data.getPKey()))
			.orElseThrow(() -> new CFLibCollisionDetectedException(getClass(), S_ProcName, data.getPKey()));
		if (existing.getRequiredRevision() != data.getRequiredRevision()) {
			throw new CFLibCollisionDetectedException(getClass(), S_ProcName, data.getPKey());
		}
		// Apply superior data relationships of CFSecSecSysRole to existing object
		// Apply data columns of CFSecSecSysRole to existing object
		existing.setRequiredName(data.getRequiredName());
		// Update the audit columns
		data.setUpdatedAt(LocalDateTime.now());
		// Save the changes we've made
		return cfsec31SecSysRoleRepository.save(existing);
	}

	/**
	 *	Argument-based find database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredSecSysRoleId
	 *
	 *		@return The retrieved entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRole find(@Param("secSysRoleId") ICFLibKeyHash256 requiredSecSysRoleId) {
		return( cfsec31SecSysRoleRepository.get(requiredSecSysRoleId));
	}

	/**
	 *	Retrieve all entities from the repository
	 *
	 *		@return The list of retrieved entities, which may be empty
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecSysRole> findAll() {
		return( cfsec31SecSysRoleRepository.findAll() );
	}

	// CFSecSecSysRole specified index finders

	/**
	 *	Find an entity using the columns of the ICFSecSecSysRoleByUNameIdxKey as arguments.
	 *
	 *		@param requiredName
	 *
	 *		@return The found entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRole findByUNameIdx(@Param("name") String requiredName) {
		return( cfsec31SecSysRoleRepository.findByUNameIdx(requiredName));
	}

	/**
	 *	ICFSecSecSysRoleByUNameIdxKey entity finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecSecSysRoleByUNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRole findByUNameIdx(ICFSecSecSysRoleByUNameIdxKey key) {
		return( cfsec31SecSysRoleRepository.findByUNameIdx(key.getRequiredName()));
	}

	// CFSecSecSysRole specified lock-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRole lockByIdIdx(@Param("secSysRoleId") ICFLibKeyHash256 requiredSecSysRoleId) {
		return( cfsec31SecSysRoleRepository.lockByIdIdx(requiredSecSysRoleId));
	}

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredName
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRole lockByUNameIdx(@Param("name") String requiredName) {
		return( cfsec31SecSysRoleRepository.lockByUNameIdx(requiredName));
	}

	/**
	 *	ICFSecSecSysRoleByUNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecSysRole lockByUNameIdx(ICFSecSecSysRoleByUNameIdxKey key) {
		return( cfsec31SecSysRoleRepository.lockByUNameIdx(key.getRequiredName()));
	}

	// CFSecSecSysRole specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByIdIdx(@Param("secSysRoleId") ICFLibKeyHash256 requiredSecSysRoleId) {
		cfsec31SecSysRoleRepository.deleteByIdIdx(requiredSecSysRoleId);
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredName
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByUNameIdx(@Param("name") String requiredName) {
		cfsec31SecSysRoleRepository.deleteByUNameIdx(requiredName);
	}

	/**
	 *	ICFSecSecSysRoleByUNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecSysRoleByUNameIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByUNameIdx(ICFSecSecSysRoleByUNameIdxKey key) {
		cfsec31SecSysRoleRepository.deleteByUNameIdx(key.getRequiredName());
	}

}
